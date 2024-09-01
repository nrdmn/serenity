/*
 * Copyright (c) 2018-2020, Andreas Kling <kling@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Array.h>
#include <AK/Endian.h>
#include <AK/Format.h>
#include <AK/Optional.h>
#include <AK/SipHash.h>
#include <AK/StringView.h>

#ifdef KERNEL
#    include <AK/Error.h>
#    include <Kernel/Library/KString.h>
#else
#    include <AK/ByteString.h>
#    include <AK/String.h>
#endif

namespace AK {

class [[gnu::packed]] IPv4Address {
public:
    using in_addr_t = u32;

    constexpr IPv4Address() = default;

    constexpr IPv4Address(u32 a, u32 b, u32 c, u32 d)
    {
        m_data = (d << 24) | (c << 16) | (b << 8) | a;
    }

    constexpr IPv4Address(u8 const data[4])
    {
        m_data = (u32(data[3]) << 24) | (u32(data[2]) << 16) | (u32(data[1]) << 8) | u32(data[0]);
    }

    constexpr IPv4Address(NetworkOrdered<u32> address)
        : m_data(address)
    {
    }

    constexpr u8 operator[](int i) const
    {
        VERIFY(i >= 0 && i < 4);
        return octet(i);
    }

#ifdef KERNEL
    ErrorOr<NonnullOwnPtr<Kernel::KString>> to_string() const
    {
        return Kernel::KString::formatted("{}.{}.{}.{}",
            octet(0),
            octet(1),
            octet(2),
            octet(3));
    }
#else
    ByteString to_byte_string() const
    {
        return ByteString::formatted("{}.{}.{}.{}",
            octet(0),
            octet(1),
            octet(2),
            octet(3));
    }

    ByteString to_byte_string_reversed() const
    {
        return ByteString::formatted("{}.{}.{}.{}",
            octet(3),
            octet(2),
            octet(1),
            octet(0));
    }

    ErrorOr<String> to_string() const
    {
        return String::formatted("{}.{}.{}.{}",
            octet(0),
            octet(1),
            octet(2),
            octet(3));
    }
#endif

    static constexpr Optional<IPv4Address> from_string(StringView string)
    {
        if (string.is_empty()) {
            return {};
        }

        // parser state
        int nr_octet = 0;
        bool has_read_one_digit = false;
        bool has_read_zero_first = false;
        Array<u64, 4> parts {};

        for (auto const ch : string) {
            switch (ch) {
            case '.':
                // only the last part may be larger than 255
                if (parts[nr_octet] > 255) {
                    return {};
                }
                // no '.' as first character
                // no consecutive '.'
                if (!has_read_one_digit) {
                    return {};
                }
                has_read_one_digit = false;
                has_read_zero_first = false;
                nr_octet++;
                // IP address must not have more than 4 parts
                if (nr_octet > 3) {
                    return {};
                }
                break;
            case '0':
                if (!has_read_one_digit) {
                    has_read_zero_first = true;
                }
                [[fallthrough]];
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                parts[nr_octet] *= 10;
                // assuming ASCII-like character ordering for digits
                parts[nr_octet] += ch - '0';
                // first  part must be <= 0xffff'ffff
                // second part must be <= 0xff'ffff
                // third  part must be <= 0xffff
                // fourth part must be <= 0xff
                if (parts[nr_octet] > (0xffff'ffffULL >> (nr_octet * 8))) {
                    return {};
                }
                // number must have no leading zeros
                if (has_read_zero_first && has_read_one_digit) {
                    return {};
                }
                has_read_one_digit = true;
                break;
            default:
                // invalid character
                return {};
            }
        }

        // an IP address must end in a digit
        if (!has_read_one_digit) {
            return {};
        }

        switch (nr_octet) {
        case 0:
            return IPv4Address {
                u8(parts[0] >> 24),
                u8((parts[0] >> 16) % 0x100),
                u8((parts[0] >> 8) % 0x100),
                u8(parts[0] % 0x100),
            };
        case 1:
            return IPv4Address {
                u8(parts[0]),
                u8((parts[1] >> 16) % 0x100),
                u8((parts[1] >> 8) % 0x100),
                u8(parts[1] % 0x100),
            };
        case 2:
            return IPv4Address {
                u8(parts[0]),
                u8(parts[1]),
                u8((parts[2] >> 8) % 0x100),
                u8(parts[2] % 0x100),
            };
        case 3:
            return IPv4Address {
                u8(parts[0]),
                u8(parts[1]),
                u8(parts[2]),
                u8(parts[3]),
            };
        default:
            // we've checked this earlier
            VERIFY_NOT_REACHED();
        }
    }

    static constexpr IPv4Address netmask_from_cidr(int cidr)
    {
        VERIFY(cidr >= 0 && cidr <= 32);
        u32 value = 0xffffffffull << (32 - cidr);
        return IPv4Address((value & 0xff000000) >> 24, (value & 0xff0000) >> 16, (value & 0xff00) >> 8, (value & 0xff));
    }

    constexpr in_addr_t to_in_addr_t() const { return m_data; }
    constexpr u32 to_u32() const { return m_data; }

    constexpr bool operator==(IPv4Address const& other) const = default;
    constexpr bool operator!=(IPv4Address const& other) const = default;

    constexpr bool is_zero() const
    {
        return m_data == 0u;
    }

private:
    constexpr u32 octet(int n) const
    {
        VERIFY(n >= 0 && n <= 3);
        constexpr auto bits_per_byte = 8;
        auto const bits_to_shift = bits_per_byte * n;
        return (m_data >> bits_to_shift) & 0x0000'00FF;
    }

    u32 m_data {};
};

static_assert(sizeof(IPv4Address) == 4);

template<>
struct Traits<IPv4Address> : public DefaultTraits<IPv4Address> {
    static unsigned hash(IPv4Address const& address) { return secure_sip_hash(static_cast<u64>(address.to_u32())); }
};

#ifdef KERNEL
template<>
struct Formatter<IPv4Address> : Formatter<StringView> {
    ErrorOr<void> format(FormatBuilder& builder, IPv4Address value)
    {
        return Formatter<StringView>::format(builder, TRY(value.to_string())->view());
    }
};
#else
template<>
struct Formatter<IPv4Address> : Formatter<StringView> {
    ErrorOr<void> format(FormatBuilder& builder, IPv4Address value)
    {
        return Formatter<StringView>::format(builder, value.to_byte_string());
    }
};
#endif

}

#if USING_AK_GLOBALLY
using AK::IPv4Address;
#endif
