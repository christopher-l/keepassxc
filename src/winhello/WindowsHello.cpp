/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "WindowsHello.h"

#include <winrt/base.h>
#include <winrt/windows.foundation.h>
#include <winrt/windows.security.credentials.h>
#include <winrt/windows.security.cryptography.h>

#include "core/AsyncTask.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Credentials;
using namespace Windows::Security::Cryptography;
using namespace Windows::Storage::Streams;

namespace
{
    const std::wstring s_winHelloKeyName{L"keepassxc_winhello"};
    constexpr int s_winHelloKeySize = 32;
    constexpr int s_winHelloIVSize = 16;
} // namespace

WindowsHello* WindowsHello::m_instance{nullptr};
WindowsHello* WindowsHello::instance()
{
    if (!m_instance) {
        m_instance = new WindowsHello();
    }
    return m_instance;
}

WindowsHello::WindowsHello(QObject* parent)
    : QObject(parent)
{
    concurrency::create_task([this] {
        bool state = KeyCredentialManager::IsSupportedAsync().get();
        m_available = state;
        emit availableChanged(m_available);
    });
}

bool WindowsHello::isAvailable() const
{
    return m_available;
}

QString WindowsHello::errorString() const
{
    return m_error;
}

bool WindowsHello::storeKey(const QString& dbPath, const QByteArray& data)
{
    m_error.clear();
    return AsyncTask::runAndWaitForFuture([&] {
        // The first time this is used a key-pair will be generated using the common name
        auto result =
            KeyCredentialManager::RequestCreateAsync(s_winHelloKeyName, KeyCredentialCreationOption::FailIfExists)
                .get();

        if (result.Status() == KeyCredentialStatus::CredentialAlreadyExists) {
            result = KeyCredentialManager::OpenAsync(s_winHelloKeyName).get();
        } else if (result.Status() != KeyCredentialStatus::Success) {
            m_error = tr("Failed to create Windows Hello credential.");
            return false;
        }

        // Generate a random challenge that will be signed by Windows Hello
        // to create the key. The challenge is also used as the IV.
        const auto challenge = CryptographicBuffer::GenerateRandom(s_winHelloIVSize);

        const auto signature = result.Credential().RequestSignAsync(challenge).get();
        if (signature.Status() != KeyCredentialStatus::Success) {
            m_error = tr("Failed to sign challenge using Windows Hello.");
            return false;
        }

        // Use the challenge signature (first 32 bytes) as the encryption key
        // and the original challenge as the IV.
        QByteArray key(reinterpret_cast<const char*>(signature.Result().data()), s_winHelloKeySize);
        QByteArray iv(reinterpret_cast<const char*>(challenge.data()), s_winHelloIVSize);

        // Encrypt the data using AES-256-CBC
        SymmetricCipher cipher;
        if (!cipher.init(SymmetricCipher::Aes256_CBC, SymmetricCipher::Encrypt, key, iv)) {
            m_error = tr("Failed to init KeePassXC crypto.");
            return false;
        }
        QByteArray encrypted = data;
        if (!cipher.finish(encrypted)) {
            m_error = tr("Failed to encrypt key data.");
            return false;
        }

        // Prepend the challenge/IV to the encrypted data
        encrypted.prepend(iv);
        m_encryptedKeys.insert(dbPath, encrypted);
        return true;
    });
}

bool WindowsHello::retrieveKey(const QString& dbPath, QByteArray& data)
{
    data.clear();
    m_error.clear();
    if (!containsKey(dbPath)) {
        m_error = tr("Failed to get Windows Hello credential.");
        return false;
    }

    return AsyncTask::runAndWaitForFuture([&] {
        // Try to open the shared signing key
        const auto result = KeyCredentialManager::OpenAsync(s_winHelloKeyName).get();
        if (result.Status() != KeyCredentialStatus::Success) {
            m_error = tr("Failed to get Windows Hello credential.");
            return false;
        }

        // Read the previously used challenge and encrypted data
        const auto& keydata = m_encryptedKeys.value(dbPath);
        const auto iv = keydata.left(s_winHelloIVSize);
        const auto encrypted = keydata.mid(s_winHelloIVSize);

        const auto challenge = CryptographicBuffer::CreateFromByteArray(
            {reinterpret_cast<const uint8_t*>(iv.data()), reinterpret_cast<const uint8_t*>(iv.data() + iv.size())});

        // Sign the challenge to create the encryption key (first 32 bytes)
        const auto signature = result.Credential().RequestSignAsync(challenge).get();
        if (signature.Status() != KeyCredentialStatus::Success) {
            m_error = tr("Failed to sign challenge using Windows Hello.");
            return false;
        }

        QByteArray key(reinterpret_cast<const char*>(signature.Result().data()), s_winHelloKeySize);

        // Decrypt the data using the generated key and IV from above
        SymmetricCipher cipher;
        if (!cipher.init(SymmetricCipher::Aes256_CBC, SymmetricCipher::Decrypt, key, iv)) {
            m_error = tr("Failed to init KeePassXC crypto.");
            return false;
        }

        // Store the decrypted data into the passed parameter
        data = encrypted;
        if (!cipher.finish(data)) {
            data.clear();
            m_error = tr("Failed to decrypt key data.");
            return false;
        }

        return true;
    });
}

void WindowsHello::removeKey(const QString& dbPath)
{
    m_encryptedKeys.remove(dbPath);
}

bool WindowsHello::containsKey(const QString& dbPath) const
{
    return m_encryptedKeys.contains(dbPath);
}

void WindowsHello::reset()
{
    concurrency::create_task([&] { KeyCredentialManager::DeleteAsync(s_winHelloKeyName); });
    m_encryptedKeys.clear();
}
