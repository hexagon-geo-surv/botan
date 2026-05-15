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

//static
bool DNSName::host_wildcard_match(std::string_view issued, std::string_view host) {
   if(host.empty() || issued.empty()) {
      return false;
   }

   // Maximum valid DNS name
   if(host.size() > 253) {
      return false;
   }

   /*
   The wildcard if existing absorbs (host.size() - issued.size() + 1) chars,
   which must be non-negative. So issued cannot possibly exceed host.size() + 1.
   */
   if(issued.size() > host.size() + 1) {
      return false;
   }

   /*
   If there are embedded nulls in your issued name
   Well I feel bad for you son
   */
   if(issued.find('\0') != std::string_view::npos) {
      return false;
   }

   // '*' is not a valid character in DNS names so should not appear on the host side
   if(host.find('*') != std::string_view::npos) {
      return false;
   }

   // Similarly a DNS name can't end in .
   if(host.back() == '.') {
      return false;
   }

   // And a host can't have an empty name component, so reject that
   if(host.find("..") != std::string_view::npos) {
      return false;
   }

   // ASCII-only case-insensitive char equality, avoids locale overhead from tolower
   auto dns_char_eq = [](char a, char b) -> bool {
      if(a == b) {
         return true;
      }
      const auto la = static_cast<unsigned char>(a | 0x20);
      const auto lb = static_cast<unsigned char>(b | 0x20);
      return la == lb && la >= 'a' && la <= 'z';
   };

   auto dns_char_eq_range = [&](std::string_view a, std::string_view b) -> bool {
      if(a.size() != b.size()) {
         return false;
      }
      for(size_t i = 0; i != a.size(); ++i) {
         if(!dns_char_eq(a[i], b[i])) {
            return false;
         }
      }
      return true;
   };

   // Exact match: accept
   if(dns_char_eq_range(issued, host)) {
      return true;
   }

   // First detect offset of wildcard '*' if included
   const size_t first_star = issued.find('*');
   const bool has_wildcard = (first_star != std::string_view::npos);

   // At most one wildcard is allowed
   if(has_wildcard && issued.find('*', first_star + 1) != std::string_view::npos) {
      return false;
   }

   // If no * at all then not a wildcard, and so not a match
   if(!has_wildcard) {
      return false;
   }

   /*
   Now walk through the issued string, making sure every character
   matches. When we come to the (singular) '*', jump forward in the
   hostname by the corresponding amount. We know exactly how much
   space the wildcard takes because it must be exactly `len(host) -
   len(issued) + 1 chars`.

   We also verify that the '*' comes in the leftmost component, and
   doesn't skip over any '.' in the hostname.
   */
   size_t dots_seen = 0;
   size_t host_idx = 0;

   for(size_t i = 0; i != issued.size(); ++i) {
      if(issued[i] == '.') {
         dots_seen += 1;
      }

      if(issued[i] == '*') {
         // Fail: wildcard can only come in leftmost component
         if(dots_seen > 0) {
            return false;
         }

         /*
         Since there is only one * we know the tail of the issued and
         hostname must be an exact match. In this case advance host_idx
         to match.
         */
         const size_t advance = (host.size() - issued.size() + 1);

         if(host_idx + advance > host.size()) {  // shouldn't happen
            return false;
         }

         // Can't be any intervening .s that we would have skipped
         for(size_t k = host_idx; k != host_idx + advance; ++k) {
            if(host[k] == '.') {
               return false;
            }
         }

         host_idx += advance;
      } else {
         if(!dns_char_eq(issued[i], host[host_idx])) {
            return false;
         }

         host_idx += 1;
      }
   }

   // Wildcard issued name must have at least 3 components
   if(dots_seen < 2) {
      return false;
   }

   return true;
}

}  // namespace Botan
