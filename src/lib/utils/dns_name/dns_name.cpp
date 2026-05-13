/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dns_name.h>

#include <botan/exceptn.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

/*
* Validate @p name as an RFC 1035 / 1123 DNS name and return its
* lowercased canonical form. Throws Decoding_Error if @p name is not
* a valid DNS name. A "*" label is accepted so SAN wildcard entries
* round-trip through this validator unchanged.
*/
std::string check_and_canonicalize_dns_name(std::string_view name) {
   if(name.size() > 255) {
      throw Decoding_Error("DNS name exceeds maximum allowed length");
   }

   if(name.empty()) {
      throw Decoding_Error("DNS name cannot be empty");
   }

   if(name.starts_with(".") || name.ends_with(".")) {
      throw Decoding_Error("DNS name cannot start or end with a dot");
   }

   /*
   * Table mapping uppercase to lowercase and only including values valid for
   * DNS names: A-Z, a-z, 0-9, '-', '.', plus '*' for wildcarding (RFC 1035)
   */
   // clang-format off
   constexpr uint8_t DNS_CHAR_MAPPING[128] = {
      '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
      '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
      '\0', '\0', '\0', '\0',  '*', '\0', '\0',  '-',  '.', '\0',  '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',
       '9', '\0', '\0', '\0', '\0', '\0', '\0', '\0',  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',
       'l',  'm',  'n',  'o',  'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z', '\0', '\0', '\0', '\0',
       '\0', '\0',  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',  'p',  'q',
       'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z', '\0', '\0', '\0', '\0', '\0',
   };
   // clang-format on

   std::string canon;
   canon.reserve(name.size());

   // RFC 1035: DNS labels must not exceed 63 characters
   size_t current_label_length = 0;

   for(size_t i = 0; i != name.size(); ++i) {
      const char c = name[i];

      if(c == '.') {
         if(i > 0 && name[i - 1] == '.') {
            throw Decoding_Error("DNS name contains sequential period chars");
         }

         if(current_label_length == 0) {
            throw Decoding_Error("DNS name contains empty label");
         }
         current_label_length = 0;  // Reset for next label
      } else {
         current_label_length++;

         if(current_label_length > 63) {  // RFC 1035 Maximum DNS label length
            throw Decoding_Error("DNS name label exceeds maximum length of 63 characters");
         }
      }

      const uint8_t cu = static_cast<uint8_t>(c);
      if(cu >= 128) {
         throw Decoding_Error("DNS name must not contain any extended ASCII code points");
      }
      const uint8_t mapped = DNS_CHAR_MAPPING[cu];
      if(mapped == 0) {
         throw Decoding_Error("DNS name includes invalid character");
      }

      if(mapped == '-') {
         if(i == 0 || (i > 0 && name[i - 1] == '.')) {
            throw Decoding_Error("DNS name has label with leading hyphen");
         } else if(i == name.size() - 1 || (i < name.size() - 1 && name[i + 1] == '.')) {
            throw Decoding_Error("DNS name has label with trailing hyphen");
         }
      }
      canon.push_back(static_cast<char>(mapped));
   }

   if(current_label_length == 0) {
      throw Decoding_Error("DNS name contains empty label");
   }
   return canon;
}

}  // namespace

//static
std::optional<DNSName> DNSName::from_string(std::string_view name) {
   try {
      auto canon = check_and_canonicalize_dns_name(name);
      if(canon.find('*') != std::string::npos) {
         return std::nullopt;
      }
      return DNSName(std::move(canon));
   } catch(Decoding_Error&) {
      return std::nullopt;
   }
}

//static
std::optional<DNSName> DNSName::from_san_string(std::string_view name) {
   try {
      auto canon = check_and_canonicalize_dns_name(name);
      // Validate the wildcard shape: at most one "*", and if present
      // it must be in the leftmost label (no "." before it). This
      // matches the RFC 6125 6.4.3 form that host_wildcard_match
      // accepts and rejects shapes like "*.*.example.com" or
      // "foo.*.example.com" that could never produce a match.
      const auto first_star = canon.find('*');
      if(first_star != std::string::npos) {
         if(canon.find('*', first_star + 1) != std::string::npos) {
            return std::nullopt;
         }
         const auto first_dot = canon.find('.');
         if(first_dot != std::string::npos && first_dot < first_star) {
            return std::nullopt;
         }
      }
      return DNSName(std::move(canon));
   } catch(Decoding_Error&) {
      return std::nullopt;
   }
}

bool DNSName::matches_wildcard(std::string_view wildcard) const {
   return host_wildcard_match(wildcard, m_name);
}

}  // namespace Botan
