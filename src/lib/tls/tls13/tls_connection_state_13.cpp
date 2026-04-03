/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_connection_state_13.h>

namespace Botan::TLS {

Active_Connection_State_13::~Active_Connection_State_13() = default;
Active_Connection_State_13::Active_Connection_State_13(Active_Connection_State_13&&) noexcept = default;
Active_Connection_State_13& Active_Connection_State_13::operator=(Active_Connection_State_13&&) noexcept = default;

Active_Connection_State_13::Active_Connection_State_13(Protocol_Version version,
                                                       uint16_t ciphersuite_code,
                                                       std::span<const uint8_t> client_random,
                                                       std::string application_protocol,
                                                       std::vector<X509_Certificate> peer_certs,
                                                       std::shared_ptr<const Public_Key> peer_raw_public_key,
                                                       std::optional<std::string> psk_identity,
                                                       std::string sni_hostname,
                                                       bool peer_supports_psk_dhe_ke) :
      m_version(version),
      m_ciphersuite_code(ciphersuite_code),
      m_application_protocol(std::move(application_protocol)),
      m_peer_certs(std::move(peer_certs)),
      m_client_random(client_random.begin(), client_random.end()),
      m_psk_identity(std::move(psk_identity)),
      m_peer_raw_public_key(std::move(peer_raw_public_key)),
      m_sni_hostname(std::move(sni_hostname)),
      m_peer_supports_psk_dhe_ke(peer_supports_psk_dhe_ke) {}

}  // namespace Botan::TLS
