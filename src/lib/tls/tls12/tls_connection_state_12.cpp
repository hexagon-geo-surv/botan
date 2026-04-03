/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_connection_state_12.h>

#include <botan/internal/tls_handshake_io.h>

namespace Botan::TLS {

Active_Connection_State_12::~Active_Connection_State_12() = default;
Active_Connection_State_12::Active_Connection_State_12(Active_Connection_State_12&&) noexcept = default;
Active_Connection_State_12& Active_Connection_State_12::operator=(Active_Connection_State_12&&) noexcept = default;

void Active_Connection_State_12::set_dtls_handshake_io(std::unique_ptr<Handshake_IO> io) {
   m_dtls_handshake_io = std::move(io);
}

Active_Connection_State_12::Active_Connection_State_12(Protocol_Version version,
                                                       uint16_t ciphersuite_code,
                                                       std::span<const uint8_t> client_random,
                                                       std::string application_protocol,
                                                       std::vector<X509_Certificate> peer_certs,
                                                       std::optional<std::string> psk_identity,
                                                       std::span<const uint8_t> server_random,
                                                       Session_ID session_id,
                                                       secure_vector<uint8_t> master_secret,
                                                       std::string prf_algo,
                                                       bool client_supports_secure_renegotiation,
                                                       bool server_supports_secure_renegotiation,
                                                       std::vector<uint8_t> client_finished_verify_data,
                                                       std::vector<uint8_t> server_finished_verify_data,
                                                       bool supports_extended_master_secret) :
      m_version(version),
      m_ciphersuite_code(ciphersuite_code),
      m_application_protocol(std::move(application_protocol)),
      m_peer_certs(std::move(peer_certs)),
      m_client_random(client_random.begin(), client_random.end()),
      m_psk_identity(std::move(psk_identity)),
      m_server_random(server_random.begin(), server_random.end()),
      m_session_id(std::move(session_id)),
      m_master_secret(std::move(master_secret)),
      m_prf_algo(std::move(prf_algo)),
      m_client_supports_secure_renegotiation(client_supports_secure_renegotiation),
      m_server_supports_secure_renegotiation(server_supports_secure_renegotiation),
      m_client_finished_verify_data(std::move(client_finished_verify_data)),
      m_server_finished_verify_data(std::move(server_finished_verify_data)),
      m_supports_extended_master_secret(supports_extended_master_secret) {}

}  // namespace Botan::TLS
