/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMAIL_ADDRESS_H_
#define BOTAN_EMAIL_ADDRESS_H_

#include <botan/dns_name.h>
#include <botan/types.h>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

/**
* A parsed email address in mailbox form: "local-part@domain".
*/
class BOTAN_PUBLIC_API(3, 13) EmailAddress final {
   public:
      static std::optional<EmailAddress> from_string(std::string_view addr);

      /// The local-part, ASCII only
      const std::string& local_part() const { return m_local_part; }

      const DNSName& domain() const { return m_domain; }

      std::string to_string() const;

      auto operator<=>(const EmailAddress&) const = default;
      bool operator==(const EmailAddress&) const = default;

   private:
      EmailAddress(std::string local_part, DNSName domain) :
            m_local_part(std::move(local_part)), m_domain(std::move(domain)) {}

      std::string m_local_part;
      DNSName m_domain;
};

/**
* A parsed internationalized mailbox (`SmtpUTF8Mailbox`) as defined by
* RFC 9598. The mailbox is `local-part "@" domain`, where local-part
* is allowed to be UTF-8
*/
class BOTAN_PUBLIC_API(3, 13) SmtpUtf8Mailbox final {
   public:
      static std::optional<SmtpUtf8Mailbox> from_string(std::string_view addr);

      /// The local-part, UTF-8 encoded, may contain non-ASCII
      const std::string& local_part() const { return m_local_part; }

      /// The domain, as an LDH host name in A-label form (RFC 9598 Section 3)
      const DNSName& domain() const { return m_domain; }

      std::string to_string() const;

      auto operator<=>(const SmtpUtf8Mailbox&) const = default;
      bool operator==(const SmtpUtf8Mailbox&) const = default;

   private:
      SmtpUtf8Mailbox(std::string local_part, DNSName domain) :
            m_local_part(std::move(local_part)), m_domain(std::move(domain)) {}

      std::string m_local_part;
      DNSName m_domain;
};

}  // namespace Botan

#endif
