//
//  StandAloneHTTPSignature.swift
//
//  Created by Thomas Haymore on 1/31/22.
//

import Foundation
import CryptoKit

class StandAloneHTTPSignature {
    
    private var secretKey: String
    private var sharedSecret: String
    
    var host: String
    var method: String
    var target: String
    var merchantId: String
    
    init (host: String, method: String, target: String) {
        
        self.secretKey = ""
        self.sharedSecret = ""
        self.merchantId = ""
        
        self.host = host
        self.method = method
        self.target = target
    }
    
    func getSignature() -> String {
        // Prep and add HTTP signature
        let signatureBase = "keyid=\"\(self.secretKey)\", algorithm=\"HmacSHA256\", headers=\"host date (request-target) v-c-merchant-id\","
        
        // Create datetime string
        let dateFormat = DateFormatter()
        dateFormat.dateFormat = "EEE',' dd MMM yyyy HH':'mm':'ss z"
        dateFormat.timeZone = TimeZone(identifier:"GMT")
        let dateString = dateFormat.string(from: Date())
        
        // Create signature hash
        var headersForSig = "host: \(self.host)\n"
        headersForSig += "date: \(dateString)\n"
        headersForSig += "(request-target): \(self.method) \(self.target)\n"
        headersForSig += "v-c-merchant-id: \(self.merchantId)"
        
        let base64Secret = Data(base64Encoded: self.sharedSecret)!
        let keyForHash = SymmetricKey(data: base64Secret)
        let signatureHash = HMAC<SHA256>.authenticationCode(for: headersForSig.data(using: .utf8)!, using: keyForHash)
        
        let basedSignatureHash = Data(signatureHash).base64EncodedString()
        
        let fullSignature = signatureBase + "signature=\"\(basedSignatureHash)\""
        
        return fullSignature
    }
    
}
