//
//  SNIParser.swift
//  SNIParser
//
//  Created by Vladislav Simovic on 27.12.24..
//

import Foundation
import OpenSSL

final class SNIParser {
    
    static let shared = SNIParser()
    
    let clientHelloPacket: [UInt8] = [
        // TLS Record Header
        0x16, 0x03, 0x01, 0x00, 0x5d,                // Content Type (0x16 = Handshake), Version (0x0301 = TLS 1.0), Length (93 bytes)

        // Handshake Header
        0x01, 0x00, 0x00, 0x59,                      // Handshake Type (0x01 = ClientHello), Length (89 bytes)

        // ClientHello
        0x03, 0x03,                                  // Version (0x0303 = TLS 1.2)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20,

        0x00,                                        // Session ID Length (0 bytes)
        0x00, 0x02,                                  // Cipher Suites Length (2 bytes)
        0x13, 0x01,                                  // Cipher Suite (0x1301 = TLS_AES_128_GCM_SHA256)
        0x01,                                        // Compression Methods Length (1 byte)
        0x00,                                        // Compression Method (0x00 = None)

        // Extensions
        0x00, 0x28,                                  // Extensions Length (40 bytes)

        // SNI Extension
        0x00, 0x00,                                  // Extension Type (0x0000 = Server Name)
        0x00, 0x18,                                  // Extension Length (24 bytes)
        0x00, 0x16,                                  // Server Name List Length (22 bytes)
        0x00,                                        // Server Name Type (0x00 = Host Name)
        0x00, 0x13,                                  // Server Name Length (19 bytes)
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,    // Server Name ("example.com")
        0x2e, 0x63, 0x6f, 0x6d,                      // Server Name continued
        0x00                                         // End
    ]
    
    let clientHelloPacket2: [UInt8] = [
        // TLS Record Header
        0x16, 0x03, 0x01, 0x00, 0x54,                // Content Type (0x16 = Handshake), Version (0x0301 = TLS 1.0), Length (84 bytes)

        // Handshake Header
        0x01, 0x00, 0x00, 0x50,                      // Handshake Type (0x01 = ClientHello), Length (80 bytes)

        // ClientHello
        0x03, 0x03,                                  // Version (0x0303 = TLS 1.2)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20,

        0x00,                                        // Session ID Length (0 bytes)
        0x00, 0x02,                                  // Cipher Suites Length (2 bytes)
        0x13, 0x01,                                  // Cipher Suite (TLS_AES_128_GCM_SHA256)
        0x01,                                        // Compression Methods Length (1 byte)
        0x00,                                        // Compression Method (No compression)

        // Extensions
        0x00, 0x26,                                  // Extensions Length (38 bytes)

        // SNI Extension
        0x00, 0x00,                                  // Extension Type (0x0000 = Server Name)
        0x00, 0x20,                                  // Extension Length (32 bytes)
        0x00, 0x1e,                                  // Server Name List Length (30 bytes)
        0x00,                                        // Server Name Type (0x00 = Host Name)
        0x00, 0x1b,                                  // Server Name Length (27 bytes)
        0x74, 0x65, 0x73, 0x74, 0x2e, 0x65, 0x78,    // Server Name ("test.example.com")
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d                                    // End of Server Name
    ]
    
    func execute() {
//        print(process(Data(clientHello())) ?? "No value")
        print("\(clientHelloPacket)")
        let value = extractSNI3(from: clientHello())
        print(value ?? "No value")
    }
    
    private func process(_ packet: Data) -> String? {
        let sni = packet.withUnsafeBytes { ptr -> String? in
            guard let baseAddress = ptr.baseAddress else { return nil }
            guard let sni = extract_sni(baseAddress, packet.count) else { return nil }
            return String(cString: sni)
        }
        
        return sni
    }
    
    private func extract_sni2(_ baseAddress: UnsafeRawPointer, _ size: Int) -> UnsafePointer<CChar>? {
        // Create SSL context
        guard let ctx = SSL_CTX_new(TLS_client_method()) else {
            Logger.shared.log(message: "Failed to create SSL context")
            return nil
        }
        defer { SSL_CTX_free(ctx) }
        
        // Create SSL object
        guard let ssl = SSL_new(ctx) else {
            Logger.shared.log(message: "Failed to create SSL object")
            return nil
        }
        defer { SSL_free(ssl) }
        
        // Create BIO with packet data
        guard let bio = BIO_new_mem_buf(baseAddress, Int32(size)) else {
            Logger.shared.log(message: "Failed to create BIO")
            return nil
        }
        defer { BIO_free(bio) }
        
        // Bind BIO to SSL
        SSL_set_bio(ssl, bio, bio)
        
        // Perform handshake
        if SSL_do_handshake(ssl) <= 0 {
            Logger.shared.log(message: "Handshake failed: \(ERR_get_error())")
            return nil
        }
        
        // Get the SNI
        guard let sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) else {
            Logger.shared.log(message: "No SNI found")
            return nil
        }
        
        Logger.shared.log(message: "Extracted SNI")
        return sni
    }
    
    private func extract_sni(_ baseAddress: UnsafeRawPointer, _ size: Int) -> UnsafePointer<CChar>? {
        let ssl = SSL_new(SSL_CTX_new(TLS_client_method()))
        
        if ssl == nil {
            Logger.shared.log(message: "SSL is nil")
            return nil
        }
        
        let bio = BIO_new_mem_buf(baseAddress, Int32(size))
        if bio == nil {
            Logger.shared.log(message: "Bio is nil")
            SSL_free(ssl)
            return nil
        }
        
        SSL_set_bio(ssl, bio, bio)
        SSL_do_handshake(ssl)
        
        let sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
        
        SSL_free(ssl)
        
        Logger.shared.log(message: "Return SNI")
        return sni
    }
    
    private func clientHello() -> [UInt8] {

        let packet = """
        000000  16 03 01 00 b0 01 00 00 ac 03 03 45 36 9b 87 0e 
        000010  13 8b ce 51 fe 5b ab e1 b9 ab e7 27 3c 04 48 e2 
        000020  6d a5 eb 3e e6 03 66 59 0b b2 c6 00 00 18 c0 2b 
        000030  c0 2c cc a9 c0 2f c0 30 cc a8 c0 13 c0 14 00 9c 
        000040  00 9d 00 2f 00 35 01 00 00 6b 00 00 00 15 00 13 
        000050  00 00 10 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 
        000060  63 6f 6d 00 17 00 00 ff 01 00 01 00 00 0a 00 08 
        000070  00 06 00 1d 00 17 00 18 00 0b 00 02 01 00 00 23 
        000080  00 00 00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 
        000090  2f 31 2e 31 00 05 00 05 01 00 00 00 00 00 0d 00 
        0000a0  14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 
        0000b0  06 06 01 02 01
        """

        var tcpPayload = [UInt8]()
        let lines = packet.split(separator: "\n")

        for line in lines {
            let hexBytes = line.split(separator: " ")
            for hexByte in hexBytes {
                if hexByte.count == 2, let byte = UInt8(hexByte, radix: 16) {
                    tcpPayload.append(byte)
                }
            }
        }

        return tcpPayload
    }
    
    func extractSNI3(from payload: [UInt8]) -> String? {
        // Ensure the payload is long enough
        guard payload.count > 43 else { return nil }

        // TLS Handshake starts at byte 43 for ClientHello
        var index = 43

        // Skip session ID
        let sessionIDLength = Int(payload[index])
        index += 1 + sessionIDLength

        // Skip cipher suites
        let cipherSuitesLength = Int(payload[index]) << 8 | Int(payload[index + 1])
        index += 2 + cipherSuitesLength

        // Skip compression methods
        let compressionMethodsLength = Int(payload[index])
        index += 1 + compressionMethodsLength

        // Parse extensions
        let extensionsLength = Int(payload[index]) << 8 | Int(payload[index + 1])
        index += 2
        let extensionsEnd = index + extensionsLength

        while index < extensionsEnd {
                let extensionType = Int(payload[index]) << 8 | Int(payload[index + 1])
                let extensionLength = Int(payload[index + 2]) << 8 | Int(payload[index + 3])
                index += 4

                // Check for SNI extension (type 0x00)
                if extensionType == 0x00 {
                    let sniListLength = Int(payload[index]) << 8 | Int(payload[index + 1])
                    index += 2
                    let sniType = payload[index] // Should be 0 (host_name)
                    index += 1
                    let sniLength = Int(payload[index]) << 8 | Int(payload[index + 1])
                    index += 2
                    let sniStart = index
                    let sniEnd = sniStart + sniLength

                    if sniEnd <= payload.count, sniType == 0 {
                        return String(bytes: payload[sniStart..<sniEnd], encoding: .utf8)
                    }
                }

                index += extensionLength
            }

        return nil
    }
}
