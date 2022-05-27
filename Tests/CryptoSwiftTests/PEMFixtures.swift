//
//  PEMFixtures.swift
//
//
//  Created by Brandon Toms on 5/24/22.
//

struct PEMFixtures {
    
    // MARK: RSA Keys
    
    /// DER Format
    static let RSA_1024_PUBLIC_DER = """
    -----BEGIN RSA PUBLIC KEY-----
    MIGJAoGBANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXY
    UMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE
    3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dV
    ek9b9VAgMBAAE=
    -----END RSA PUBLIC KEY-----
    """
    
    /// RSA 1024 Public Key
    ///
    /// openssl asn1parse -i -in rsa_1024_pub.pem
    /// ```
    /// 0:d=0  hl=3 l= 159 cons: SEQUENCE
    /// 3:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 5:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 16:d=2  hl=2 l=   0 prim:   NULL
    /// 18:d=1  hl=3 l= 141 prim:  BIT STRING
    /// ```
    static let RSA_1024_PUBLIC = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUkb0ol7/oLRbfbLqcW43xtJdh
    7xQ+Vf57DWtkEpeflZ5fUTIND+s1AlTAv63NsfUX3GJ/p+5jhnl3zweTKr7e5haM
    ZqOJaARSKpGxOBwz1K3bhvJW+izXwUrwPbcmkiAlvkAsjj1hwRpND8t/NouF+hOw
    HLQCPvkX8YLbUzoZrwIDAQAB
    -----END PUBLIC KEY-----
    """
    
    /// RSA 2048 Public Key
    ///
    /// openssl asn1parse -i -in rsa_2048_pub.pem
    /// ```
    /// 0:d=0  hl=4 l= 290 cons: SEQUENCE
    /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 17:d=2  hl=2 l=   0 prim:   NULL
    /// 19:d=1  hl=4 l= 271 prim:  BIT STRING
    /// ```
    static let RSA_2048_PUBLIC = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoLE8VNgeYQxGt5x++zW
    5INUrgTGhcrgEjDt8J78xAQ9UVZdya4q1PP79UPKb3xVvFHHAKQ2tEzzgpZvv2h8
    M/DCzvltWpsZwVx5lMiDA71xucRdF5Uiy5IiVdObIEswIN/x9AE21VJEqPihzPZf
    AGKdpd8NkeaHnAnq4Pm5uJt9S+82U5iDQzufqm5S0YTTnmpmn6guCN7H2q9WENIi
    D3mKxYzmDNyzxEhpS9jMKubvGM8p4dRSFFzQlWO1mIuO0Lf2QkgZsFMNNAEZg3ww
    LP1OO288oXz8iAapfoLq3W+I2Jg4bOarHxSIvO2zSCZ1eagUCiHAtYfbWHAugoc5
    cQIDAQAB
    -----END PUBLIC KEY-----
    """
    
    /// RSA 3072 Public Key
    ///
    /// openssl asn1parse -i -in rsa_3072_pub.pem
    /// ```
    /// 0:d=0  hl=4 l= 418 cons: SEQUENCE
    /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 17:d=2  hl=2 l=   0 prim:   NULL
    /// 19:d=1  hl=4 l= 399 prim:  BIT STRING
    /// ```
    static let RSA_3072_PUBLIC = """
    -----BEGIN PUBLIC KEY-----
    MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0F50xB4o1O2y9Avm+YW2
    v9t5HHDI7kuWL/VxQE1R6FkpgLYQ0tUlB2QWGigYUhRS1f2ql1s7LXUVceUesHzH
    oXlzmt3Rnow9doASPROlyAcNrzniMyDzH6hz2xaVsaj3Kygc9evQzuf1Rq1R0/bj
    AkIlssumizfv70FZrmKBcgp5X9seC/wo3kWIRBV/Akx5vom0V6TEupy/39TDffnK
    a3rN9yb7+ZGrHMoXofkd+pYATyIbuwsjeCU0F2v6+pbkXDrB0bgsp6/FRx8Tw9CF
    gKf1JESSjeRQIk8nKXiqiNPmmOXvKH39lyEhWetcpn1E+bv7a4TAu1wy/FzLNp9w
    NxB5zLX6gqxUDM0YUpsPMftB2dlixO0yzLcvbUohceIb03L4mBsvWfQ3W7yYkzBo
    XTsPWofPw/jQY2IorGTKH4vgbQfW3fmqj1CXqgLEOe6XbWkcXyUnTp3Z24RiL5Ql
    dqZJs8yEKZqNP9/miIS83Onc1zjWovT7LLFCnucNgoOHAgMBAAE=
    -----END PUBLIC KEY-----
    """
    
    /// RSA 4096 Public Key
    ///
    /// openssl asn1parse -i -in rsa_4096_pub.pem
    /// ```
    /// 0:d=0  hl=4 l= 546 cons: SEQUENCE
    /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 17:d=2  hl=2 l=   0 prim:   NULL
    /// 19:d=1  hl=4 l= 527 prim:  BIT STRING
    /// ```
    static let RSA_4096_PUBLIC = """
    -----BEGIN PUBLIC KEY-----
    MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA96lgFtImy0lK6uxopyli
    o5WwN5FIxNdQXE6NL5o6t5Lwd3r/FCq+C1ix1Pb73lU0nJv64rCkgNn5U9rYv4e8
    /Eyu2Egp+2Ff1mBpPnNUU2oqe3de/cf8EyFR8+bQqS+cl5VSCOK2Bp87WlnjBBd7
    vy8UfjrDTIj63tNQADq/OkoUye9q7PPunTIVTvbRlC1vwVDPiCLIPUniRqAv44cG
    qM1zxRMhJTEVWJhjnaMy/NJmJQPJvnsiED3aEi/uxsUaxhpKa6JfFL8doPbeydeb
    2NE+ynG6lCYjoqmSZU+9KSwaDtutV8U8LEP9B5cHS8thdyH7uFKjGt3kgD8bVtbT
    UGL/zWWcPaqJktlM8iOh+arugW5C/fwZa1GkZZc2+Btq2MfEJ/8cSzp4nyQCk3ye
    kCQPW+7wetbqadXMpvWHFQA3HHyPEdPFF4lImSH38c0WzTWaBpXeN5dcP1T5iY+Y
    iQ7ZUSMrz8ImeYjAexHkVtE3uwaW77oBGJ33rwEXC0Agdo03mtQdKcEfB4l7gJ1G
    Tg8KWPPK0bEHew+OZxiZRfrVnGRhPVGQ5w9Kuib6Q5tP8udsEgZIZUHftf7qdscU
    kFc67jbydCj+HCD1Nvmja5u+GdJyQa021y2xbLINPaSTT1Ro8ttWRUM12Y4QEbuI
    IwumfplSdLsojGNWVCpfxAsCAwEAAQ==
    -----END PUBLIC KEY-----
    """
    
    /// RSA 1024 Private Key
    ///
    /// openssl asn1parse -i -in rsa_1024_priv.pem
    /// ```
    /// 0:d=0  hl=4 l= 630 cons: SEQUENCE
    /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 20:d=2  hl=2 l=   0 prim:   NULL
    /// 22:d=1  hl=4 l= 608 prim:  OCTET STRING      [HEX DUMP]:3082...AA50
    /// ```
    static let RSA_1024_PRIVATE = """
    -----BEGIN PRIVATE KEY-----
    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANSRvSiXv+gtFt9s
    upxbjfG0l2HvFD5V/nsNa2QSl5+Vnl9RMg0P6zUCVMC/rc2x9RfcYn+n7mOGeXfP
    B5Mqvt7mFoxmo4loBFIqkbE4HDPUrduG8lb6LNfBSvA9tyaSICW+QCyOPWHBGk0P
    y382i4X6E7ActAI++RfxgttTOhmvAgMBAAECgYAyjMnf+l5ft0FGNpQWFMunnBuX
    5YP54vdWifVs4eL+x1TXM/bkFlIH1BsVjz+kt9oiJ32g/+1364W9URVrEPI8nk5i
    Id40q3Qiozvn4ceWtSoCGmuxIbdRqL1JJn5e8Zfzs7E8KZimYu00t2qcidFDUsEC
    biCqT14UNcbpwsOpkQJBAPxMogs3OnkgCWlptZckjg+srwxnXIkzDhSO+WaKl2Dm
    DvSMnB2Ws64EDu2dP+HLiuoyqG/ZqRabdQqIsIrkLpkCQQDXr+wYGoOiL26PrAew
    z49aH/wQZq8fBM2yuwvR+ZDRraQ0otQV1aRwffqlI+IfYowJvyPX+EC/ftcff0qa
    6R+HAkAQZlrSJ9DhNrfl5j0rifDCDBOE1uMo9+yeYXzMsY2NeubV9p3fPoCHezQN
    Nf+FCdoJxykzvA5Fre05thDjtllhAkEAgdsf2M81y1KlTQi0xKXiV8+D8dfwvUsm
    EOJ+Vlfb8fGKOEqER/UNgNDIM96ryFuLll6m1ONZEDHskMERiLysRwJAawkNDlqe
    sIjqrfR2luw+TLHkMI0T6pTY9s+79F9VVV/V13v2qtTpXw1eu7Sw+oDBpJoocz/h
    +YzU+CyyzO+qUA==
    -----END PRIVATE KEY-----
    """
    
    /// RSA 2048 Private Key
    ///
    /// openssl asn1parse -i -in rsa_2048_priv.pem
    /// ```
    /// 0:d=0  hl=4 l=1214 cons: SEQUENCE
    /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 20:d=2  hl=2 l=   0 prim:   NULL
    /// 22:d=1  hl=4 l=1192 prim:  OCTET STRING      [HEX DUMP]:3082...59D7
    /// ```
    static let RSA_2048_PRIVATE = """
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGgsTxU2B5hDEa
    3nH77Nbkg1SuBMaFyuASMO3wnvzEBD1RVl3JrirU8/v1Q8pvfFW8UccApDa0TPOC
    lm+/aHwz8MLO+W1amxnBXHmUyIMDvXG5xF0XlSLLkiJV05sgSzAg3/H0ATbVUkSo
    +KHM9l8AYp2l3w2R5oecCerg+bm4m31L7zZTmINDO5+qblLRhNOeamafqC4I3sfa
    r1YQ0iIPeYrFjOYM3LPESGlL2Mwq5u8Yzynh1FIUXNCVY7WYi47Qt/ZCSBmwUw00
    ARmDfDAs/U47bzyhfPyIBql+gurdb4jYmDhs5qsfFIi87bNIJnV5qBQKIcC1h9tY
    cC6ChzlxAgMBAAECggEBAJvNVR+HbgfRvey1vEaa+4p8nUC7lMi7kyQT7RxW3FJI
    dYvaOmApZ4qeOBmm7EKWFoBousUBHcJjRxguVGSpcBogE/X4hGCBrTQ7DV2+Bj4w
    OQsxWFNDBP07o+Ey5OTyvkJ/Idp9/XhuSl9ITU2d7LBTtiHSsEbb5YGNsyCCP8bo
    OP/PQZPDgXz9vLg674rPgm32cHPIWDomspJ34EkD/szyQOpW2AM99v3NbqovM8ie
    T91266iPASTngGQG3qA54zJ91Ulu7kx+LNYpSknZOvWxrxDB8+oArdEZFuPpT5L6
    OKj5ICJCFRkiROE2xErn/nUmu4R1AA3WDnFZQMzGFAECgYEA5dDYyHUhtjlM13OL
    hUoiBWk4yzz3wB/jcvvdq8OVU0nWeuTiZh4cPSDp67q4AAffAbJvsqYomyA/Eqt/
    NNZKE7ZP9a+KFXbyd1BtDgFiVEcNGNZ0K7beQEbVlG7sFN+s8YT7eeObBoXyhhPA
    WC6fWcYfrZatCuNAmcjutoWCarECgYEA3SDViFs2Eb5II9DHwljNJF8gFgRJhAKj
    bMEGUVgSK8WWQIO2ZdzlA1kV+U0S5FXx3zyQAWVqCkdAzFB4sZjmT47NZN4cvo30
    E32rXWDoNbKpljBvEhx2HUMA+Zpdpe/vZUHlNpqGT0MZaP6nPTg79EsBdiMvVC8l
    3UC7XW5f6sECgYA1AMzutq0WxPJnAnwcOrPMAa+amC4fvnsLyvEeK1amRfJUl7Nr
    j+g9ZPjuaDsFrssNLiU6072rwW0qlikZe47MKxEX/etf9fYH9KGiSElwXI61ushC
    SMPLmUqrGEYUrl3JujzxqL/Zak08BRQogmA4KUynEYhJaY49qaz8paAlkQKBgDer
    U3avl84hvGGf5xprZsHYXOiODb/5NhFkCuYhqPlyFeCKCDpewRz1qY2ItM/dPzY3
    Nf3T/T03MP3+6FO1rY2r4tOZA12JuT/K7IBmrC8Qmpcf/GZv2eCGBNHR5e+nlvpD
    +6OihVuhBd2j9pB3/sgCtgx60Sh9cifgawsbhXRBAoGBALXBsU6d6TRU0PTOwvos
    zV4dWva41cuElT1hp4rzgSgRtUIbaFVpGi4STb/B3znvlE4VNsePgq2oe6c4Bx7l
    JwZ4bU1ZvxWZ+tLdYnelwhfgq/14tjWPGvlE+bF7s1irJIHsTsoShF+RfavhqVXF
    6FyFEjB0XDmXjJgIxkenwlnX
    -----END PRIVATE KEY-----
    """
    
    /// RSA 3072 Private Key
    ///
    /// openssl asn1parse -i -in rsa_3072_priv.pem
    /// ```
    /// 0:d=0  hl=4 l=1791 cons: SEQUENCE
    /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 20:d=2  hl=2 l=   0 prim:   NULL
    /// 22:d=1  hl=4 l=1769 prim:  OCTET STRING      [HEX DUMP]:3082...C813
    /// ```
    static let RSA_3072_PRIVATE = """
    -----BEGIN PRIVATE KEY-----
    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
    9QS5ykVryo8URNisVCornefIEw==
    -----END PRIVATE KEY-----
    """
    
    
    /// RSA 4096 Private Key
    ///
    /// openssl asn1parse -i -in rsa_4096_priv.pem
    /// ```
    /// 0:d=0  hl=4 l=2370 cons: SEQUENCE
    /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
    /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
    /// 20:d=2  hl=2 l=   0 prim:   NULL
    /// 22:d=1  hl=4 l=2348 prim:  OCTET STRING      [HEX DUMP]:3082...B4EA
    /// ```
    static let RSA_4096_PRIVATE = """
    -----BEGIN PRIVATE KEY-----
    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
    PgBeOgkLlpYxcq87zFpg5qyHdq+06g==
    -----END PRIVATE KEY-----
    """
    
    /// An encrypted RSA 1024 private key and it's original unencrypted pem file for testing AES CBC PBKDF2 decryption of PEM files...
    ///
    /// To decrypt an encrypted private RSA key...
    /// 1) Strip the headers of the PEM and base64 decode the data
    /// 2) Parse the data via ASN1 looking for the encryption algo, salt, iv and itterations used, and the ciphertext (aka octet string)
    /// 3) Derive the encryption key using PBKDF2 (sha1, salt and itterations)
    /// 4) Use encryption key to instantiate the AES CBC Cipher along with the IV
    /// 5) Decrypt the encrypted octet string
    /// 6) The decrypted octet string can be ASN1 parsed again for the private key octet string
    /// 7) This raw data can be used to instantiate a SecKey
    struct RSA_1024_PRIVATE_ENCRYPTED_PAIR {
        /// An unencrypted RSA 1024 Private Key
        ///
        /// Generated with
        /// ```
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:1024
        ///   -pkeyopt rsa_keygen_pubexp:65537
        ///   -out foo.pem
        /// ```
        static let UNENCRYPTED = """
        -----BEGIN PRIVATE KEY-----
        MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMrTsyVLP/Ureyqm
        zJDcolbO9cafCafeGXHrWJ4ar6QL+tT/apk+6kkgqvRU4QpJFurbzDXhmLpiUk9u
        t2Oy6lw0LrF7Nz/XGHXfNHutLS6+jrHI+9x55l87CQyObsdaTt1jhP3IHp6FIA/S
        rAAiCrFiPG7L97OdqREa2uWYIrupAgMBAAECgYAigSMvy/5kafI5Dkkst6wSUoDz
        Oij9WsY/YAciVm3c3YDdbVooGdDngdwzVqE2C7sPVzcFT4yY4JMaGj6ugkhl+2mm
        8BP6GkOGYbwrMgyjPXLjg4mmeQS75NxxzVFcGxM3405G4p833DxNJyFZyJpfA0b6
        5qhn4J2ZrxTwGu/TxQJBAPUxawoM1E3kRrJ+l30zHLVu0cbS4yXCYD24a9cWy6GI
        aSNnJAzsb5eGkfg7epKNIov/sTh5RLeUu9x6d3Xe0qcCQQDTxEDSmBqdB0GhQF/9
        7JXVdS25WEB4vJ/eVPPMDSoSS6IAR3+noVpQuLXqdIrAPA6alTsX1oxEKl6M6hTQ
        0lkvAkA9t2Kp9PC7amohI5wd92+Se4Jx+UMTjgmLf5AlY6d90UglkSCR4DF2gnjb
        cp03pi677nA9NskFLHrc1DadhKihAkAE443/jqVmpKk+OMc+jHy1Ddx9X+01HF2w
        e1OZjWBAReC6kuv+iboVDP6eKAyf/YL0zKctmLVqSXQfWrQaUhDfAkBNmxhdcL3M
        18PnvSVbfuwhKuNQd3lf8Xpr9eSHOnpYglqAbLObNHqZN24v+MI5M6Rdp6+yXryE
        vcUs0rZnDXkl
        -----END PRIVATE KEY-----
        """
            
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:mypassword
        /// ```
        static let ENCRYPTED = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI49PtP+7yJmgCAggA
        MB0GCWCGSAFlAwQBAgQQYz/oWtq4qhWPNrAQiO3i5wSCAoCjWvOSqAMdA4qDF8BB
        aaqGRnZ/Lvewsrs4keppFogFnYpeVkzEmeleQLIYkO2mnNvsjhfh2Vk1LW/qNPIl
        NvwjXyNbP1E6TlLmTNEAgIfyViHOCuk+17tkgAtK98huFTi0U+LbMcaxSnJ7CsNY
        9JODko7fLXMpEaGy5qcuXWsMHG1iKcggYs0J1kmWSVw9ZQP7Uh9hs31zz60kFe+T
        1I8EOjC06EcKY2HmOhzS+p378nWD3Lxi49FWkHslx1OtQwAXqMG5xWSo+kTWgmUx
        fB3Olmv7opDcQ5OtOSxRjM/6SCtrtIlPRjIS7Uu4foW2BpFS+mkkvaJR0lMiEFjA
        qMdLu3MZzT8U9lEDpd+ki+OjIC2bOXkv/OgHFmHjrTrGTVnK+HP5B0XkcaN0kmi5
        ypd8/XB4zDqO/eSSTKnDe5cvw9Ruj5vt9cesUGjckTlVlZ7Sip2nqtngEAh0k7gc
        p8p0LpNRyOM5edxNCsRLWj3Z9oskkbEFbL3INuVr6HZ5C1IpUHaxzdii1FBeLSqY
        RYCC7iOgfqRILkBN2dsnWhdLLvcVpeQqSccnNCYSrXgr40T8BqZKLnuhHT7/iZaw
        OiKp9MyygPf0wO5IFaSglpk02dohJpg/LYxFBZk+qJKPR9883NrtSPSzXxDogu2f
        /tc8OCoH919cB8WAsU1cvKYMxsr9HTfoxS7itrJX9d7tE3J2Ky7fQrPWt247BXSE
        FMUJ8BQpLL/2lNIxW9clLEuzr0RZKu3AhBU0V0o8KDucrsLPdbLvV9/J8+G8VJWB
        DZjkXrHO2Oob0rOBtz0gnIF4TSwMWlI28OFWLwN3ByGeT0KcDN7SghLtDSyEQKNW
        ZHiA
        -----END ENCRYPTED PRIVATE KEY-----
        """
    }
    
    struct RSA_1024_PRIVATE_ENCRYPTED_PAIR_2 {
        /// An unencrypted RSA 1024 Private Key
        ///
        /// Generated with
        /// ```
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:1024
        ///   -pkeyopt rsa_keygen_pubexp:65537
        ///   -out foo.pem
        /// ```
        static let UNENCRYPTED = """
        -----BEGIN PRIVATE KEY-----
        MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL/yIMg9e3A3ARX/
        TQcbNU2rKH+iFO7XmLkCsuZOIwZjf+jABxTF3D41RD65dSRql2W0V5HQW94r4M1W
        vbgEyqTSHMYxG56AxpQAke+Bu3agilzg8unrHhwWTHxGDPqEymGTdxhXUW53Hs3k
        HB74ybLWg6b9PWTqYZ81ntD5w1apAgMBAAECgYAjwIbIpWMLmMM0BLSlQTUhfWLy
        uw7pGfFRbKZD7YPqmbfmc3YeMWh/kc5fXI3sNYpzoC67czLZZBTgSmrWDtZrn/im
        iH4PIYQ8u3saFaBtOxkb3bJka0Xxsp9WL4Q97opqw6RPXtCrMZEfoxm5ePGA91J/
        C1okRSHbphg1MN8k7QJBAPCGsS5lQyrRxoUMfgcwqrwkdpd7vemkpm+eTGQHGagO
        gqpb3SdGyvViWDq/FXevRjYhwslts0/HfCI2WqDG+Q8CQQDMS1mK7maV3rGDKIxe
        s8HF2zcdkQxjPH7t+6j50RVhLtn7I+8kYWs8MBJV45Qng14zopS+iMv6/BmOQzX2
        lITHAkBB1IuP6DUu9gVAiv+/VgmUvuIaacq7tM28xPWhdvQFtBr9J3Fq+4w3Bvig
        84WboUQ1Mp5OZRDrp+yIrJm3YV3vAkEArqJCmuaLvtUsfOeuhk22+MEZbibNpg7S
        mfCkU1iNpBN+tpXTGRBFsJ+PLOhrfxNm9VCnQfCCHbxexCNj/7KZhQJACSust5DJ
        Gzi3Df1HIwMuF6xJvJuIhhxDu71nnUr/FUT1SvwxeLlphWXhPOwioftlLpOYwEOs
        rfbArbfupfGj4Q==
        -----END PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:mypassword
        /// ```
        static let ENCRYPTED_MYPASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIUmHBvqIX0ZQCAggA
        MB0GCWCGSAFlAwQBAgQQb1EhfpgHrX6I48OIObjOfQSCAoCCVCKVLUwoLThWtxTl
        dU3sKZAKU9/TK7o4FEqaw1NtZp+Y8XVj6oI50iqA8q4Lm/6vbI3Jm1UozuF59fYE
        Ruo1wVmxIrWDWqEB6dwBq5slsRW6i1vK+ljHusaM9H28YFb7Qcbs86yatPpUvjk7
        IKJRaRjkh5bTlFhgQDDcwWiXsvI5Qgu8qc3TNlllAizMTm5Z8aybsL/K32nhoYQu
        EpynV1mYqRog5ioL2cHGG7TK8x93F7kMW/IzhoXE+wVBlA4TSZDP19z8CSNdDmCQ
        vD/eZ5NXsa7W8BKB07rC4BQvaU/leTQQMs+JWD6HZXkLMqBZcWAyMiKjR07O8hpl
        1XY3zaD2wbMn8HAKrdwZRWYa+LcFaBAnouleFipX6BUvFRhugsMsmoBpxjGTc4Ou
        nV/8hQayB2zqu9kzd9ib5/RIjPUoUfuYRi0EyYNuSb1ykzxAcNGZ2oUafrQBIMAv
        Em42kcR1qXTbjbN9SIEZSkxYShkAlUZMp2XW+GvCn8XqpmA4lnxDsfyLeCJlMUKU
        kqUoGfOdVJpSIFofWcZUqGZSk/BUsKQZJ6I19EK8TjzoV7r01t2DnZGhaO1OgJjK
        xh4KdDcRX9kC9z8Tg5n1vtDqZ2b8qz5axQulUpqieZbALkccHZTI/hqI2R/Qhb3g
        0lRbRT9SqYdy6kfdfpyEBBLko93AB/9JwrhG407RbkABUozcWPoXc1Sp6ky53QPM
        HBhynYgWi5QlUjRL7JZtwacNlFQPRCHM6p2q7Xrpo95t439ThLOoip2z2wVeosG9
        WYsmdHLAKeUiRa7y9wikP0awix5++aR0qEzrog1kAcFO7Uv8cd9LC3HBKle+XJ3J
        32jj
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:
        /// ```
        static let ENCRYPTED_EMPTY_PASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIl5RVG4PUMokCAggA
        MB0GCWCGSAFlAwQBAgQQm10HTEJWJKmwgPK7N9HsgQSCAoC8uzVa/bJ1xkHEem+B
        zeRNMqEDCC7Q3TMnBmS4KwF86p8/srdDbmBJCF1Bmf7+fHmwLRnl5hAkb0zZ8QBi
        HlweMGNcmrJEeWzRPO/Egg7Y9hed87tZzHTpUohOiPWtLII8HRo/9nyFShJeTaL5
        85ptTjSFX0wXUOKQW7H4O+5x13moXrLXD99DI3VZwhmkMoxNELeffdQ8JFjxI/Sh
        4dJl3IBNZ6IkPE0aRXkpmKuH+zZHe+n1CJoxY31uXvdRH/iHGo0dp4FDQRQ4WTJ9
        wlUXHUvR5lAFjaM5+rHIuFt4DRDB6Lh/r/BWM3JUDQbBCPd4bKvq1XP0nYxEeh/J
        4a8XWwZ8fjNIjINkjx4hUaxPiitJq/u6hWeNQx9faGEfpNomvsYsbqz3w2MYjUXk
        FgPvAe86QF9udP98XwYPKbYfdi/JedyGcRsGH3v3Y9dw0q+alA4hk5iCeObRqUtm
        MZdTzz9/Lx4lmMM3iYcJc4MBxvzgdF8xuoswLSDOht6npac7hiVdHl8z4GdMni7w
        yaC6N6nq/1zFzjxKbdx+QvhkOHWBaiyKbKqZdizQ8pGelQsewubphHeAPprVDTvW
        GR243vUfk2OTITJouNyj+hXCQabKesbBHWKeGri+M/qT4lagmwaqLRIOq7aS5dt9
        e4RWrSrBE2AB2MHFj7L0glXkByBGJAsRro9KSvw+7NpJkOAZe7V2w2rRxcjdUmnd
        0mQ+qwwao8KDsRWj+esPsWa3Hp60U6nruDr1dFMp3HyZseNcaD6Fb73dLVtJ6rNa
        933Lb/Z1btCvm9pdGyscuW/qHpE92CRDUKKDAiJjrUQGg4XETt0ZzgSd8ufxyYNT
        /wVL
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:🔐
        /// ```
        static let ENCRYPTED_EMOJI_PASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIsQE5sgxXmmICAggA
        MB0GCWCGSAFlAwQBAgQQnwfzO2b0Q3g/uPubH/Og5ASCAoDCQhoXQ27c9m8kYo0L
        1Xzvxry0cwQcz7nNwb4UuyVH26nDGTZNp6cmeZfDPwYTkYj9dHNK9ubUaxQqPqrw
        V9prvSQFvBNCpXyJVVg+iRZrMHZGKu8FaziSVwliGzkOgAFd/mc6nCP1CHb82pFQ
        nIaCjaQaxzwQ0qbfwQwDgpmetT7Vx7dl6cvD7zkUBFpUB5H6bY+Wc4RYiLd82UD9
        OD1BAkjeWxS7PaGLPuaIE41H5wGtctshxk4TPsXi95GoW/EQvJH588WxCp1rSC7r
        jQPAJPkvCfRVxNt6fAMVbb4oSG0eH+Nnpoz9N13bNQ+8zGbNMFObVOxUiUUJ/hfZ
        /7ixk4CkuamfrWhjqQxgqV2umcYG9vrSX8ps5jreFmj9cpQ6E2WwzKnEzAmT9/OG
        eigXanhN3uBevZTSq5KUAnLxPNbWXKpVTASuqotdB76pHiWjej9JrGDZX5WPaDop
        21CL/PKP7dpcuUGYVY+FfeysuGppFxPav5axki7nczxbx1fmigpVa4t0SAvfD6XG
        5zW8OK8pKksM783CxEa1g142eaeOyg74TzRgMaqb70LWbaK3Vl8/8fq1Oo48jk0O
        +QYa4W6dBh67prXbQ97GX16T/ABXR0CcLrDMISqYFKjUI8CRaaOT9kpyhqtimkJg
        On8tCZjPg30/zHJ53qwJuzMCggGuAmk+0T47/dKdy6Cnx7ARxTRh+0YblIxxzkCl
        FDqHYU1grEHb4Cfdcl6NYgJlFa1C5XaPgmqalBk14a4XNIuuRerJCPToF1H3VPBC
        cGkw/Dt/Z77XclH88rgAJAVL1xan4VUG1+Bj/iAPbg/uzV+u2KJ7nKoYU6MF8o5Z
        BJVx
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-256-cbc
        ///     -passout pass:mypassword
        /// ```
        static let ENCRYPTED_MYPASSWORD_AES_256_CBC = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIjEWA/yxJuzkCAggA
        MB0GCWCGSAFlAwQBKgQQx/0wqU2Y4Eg4IlJIwVhToASCAoDQ/VePyV4gJhTOt4qf
        b8m8ka9ZwPsSnuzXREn/gI+q0n6fOmBQcM4R5VaD+R/wM8/yUeA+XD4uFW+RTIRL
        8vt7vsb0j6oPC1A0q6Cyw/QP1Kkvk3ONPgEL2ZJBYjPVpiohJA2LWjOFx3X/eCoB
        LQdNQ48p6cQZGIiaZYXf7nwJyNmHRRiJv79VDSlGL4/wPtSP4Ea3rFtoiWpYkIdR
        1GW0odXS5tbTZ5YM1kIAQWx39SLT2+9sZElZybKZb/1QNTBnlENxMrCzWbGN0v48
        qX0qTcpHBnEdS6v60pLZI/+Fk4ScUpqWlUIo7i1y/qUsvKpkNRxujx1ORW7vWzxO
        3QtI+eE9aHhNo6RolAgq1c2paBVGX0koAnT+UkhgspOukvnssjhT0alU/zSylzAq
        N3n7DInQAUgr5Dj8b53jF7nEwC9CkJcyzAlX5M+7s/Dfn6Tm6KtEtuzUIxeFTUXe
        jm63SXaaxBTWhVMN6fugji0FNkginKR4iqIw9jH3n+h8JKkJAtX/W5pk9s+lOfFh
        qRLBl4cuAMbo7OhytzO8L/dFSG1Y4fs7GJ3tvGw0c1ALEwabz2mjsBAXIV+T701O
        WFVdrGG4xr18waLcpijaDJwYnUSbXKezn23pfAQ0Z3LiAFnXXmhA/lJDNj1+pZHS
        UlcorXj/6ylbj87MFapn36lcCoC0Nz3OEA1dKE+sJQG5Els0vYALa29nRaq7SV2L
        Mr/VFagkATFV0QEYQV2q6W7pe1ywe10YmPqCNnYp8LJe+Go1Av19EadRwTkNLjRl
        QFoGtZjIpbzzC+iBeLRjy5i+W68furM8XFJFQnzZFwz7lwJINFdEg7puGgXsfLF8
        Bw7M
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// hexdump -ve '1/1 "0x%.2x, "' foo.pem
        static let UNENCRYPTED_DATA: Array<UInt8> = [
          0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
          0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x43,
          0x64, 0x67, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
          0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43, 0x41, 0x6d, 0x41, 0x77,
          0x67, 0x67, 0x4a, 0x63, 0x41, 0x67, 0x45, 0x41, 0x41, 0x6f, 0x47, 0x42, 0x41, 0x4c, 0x2f, 0x79,
          0x49, 0x4d, 0x67, 0x39, 0x65, 0x33, 0x41, 0x33, 0x41, 0x52, 0x58, 0x2f, 0x0a, 0x54, 0x51, 0x63,
          0x62, 0x4e, 0x55, 0x32, 0x72, 0x4b, 0x48, 0x2b, 0x69, 0x46, 0x4f, 0x37, 0x58, 0x6d, 0x4c, 0x6b,
          0x43, 0x73, 0x75, 0x5a, 0x4f, 0x49, 0x77, 0x5a, 0x6a, 0x66, 0x2b, 0x6a, 0x41, 0x42, 0x78, 0x54,
          0x46, 0x33, 0x44, 0x34, 0x31, 0x52, 0x44, 0x36, 0x35, 0x64, 0x53, 0x52, 0x71, 0x6c, 0x32, 0x57,
          0x30, 0x56, 0x35, 0x48, 0x51, 0x57, 0x39, 0x34, 0x72, 0x34, 0x4d, 0x31, 0x57, 0x0a, 0x76, 0x62,
          0x67, 0x45, 0x79, 0x71, 0x54, 0x53, 0x48, 0x4d, 0x59, 0x78, 0x47, 0x35, 0x36, 0x41, 0x78, 0x70,
          0x51, 0x41, 0x6b, 0x65, 0x2b, 0x42, 0x75, 0x33, 0x61, 0x67, 0x69, 0x6c, 0x7a, 0x67, 0x38, 0x75,
          0x6e, 0x72, 0x48, 0x68, 0x77, 0x57, 0x54, 0x48, 0x78, 0x47, 0x44, 0x50, 0x71, 0x45, 0x79, 0x6d,
          0x47, 0x54, 0x64, 0x78, 0x68, 0x58, 0x55, 0x57, 0x35, 0x33, 0x48, 0x73, 0x33, 0x6b, 0x0a, 0x48,
          0x42, 0x37, 0x34, 0x79, 0x62, 0x4c, 0x57, 0x67, 0x36, 0x62, 0x39, 0x50, 0x57, 0x54, 0x71, 0x59,
          0x5a, 0x38, 0x31, 0x6e, 0x74, 0x44, 0x35, 0x77, 0x31, 0x61, 0x70, 0x41, 0x67, 0x4d, 0x42, 0x41,
          0x41, 0x45, 0x43, 0x67, 0x59, 0x41, 0x6a, 0x77, 0x49, 0x62, 0x49, 0x70, 0x57, 0x4d, 0x4c, 0x6d,
          0x4d, 0x4d, 0x30, 0x42, 0x4c, 0x53, 0x6c, 0x51, 0x54, 0x55, 0x68, 0x66, 0x57, 0x4c, 0x79, 0x0a,
          0x75, 0x77, 0x37, 0x70, 0x47, 0x66, 0x46, 0x52, 0x62, 0x4b, 0x5a, 0x44, 0x37, 0x59, 0x50, 0x71,
          0x6d, 0x62, 0x66, 0x6d, 0x63, 0x33, 0x59, 0x65, 0x4d, 0x57, 0x68, 0x2f, 0x6b, 0x63, 0x35, 0x66,
          0x58, 0x49, 0x33, 0x73, 0x4e, 0x59, 0x70, 0x7a, 0x6f, 0x43, 0x36, 0x37, 0x63, 0x7a, 0x4c, 0x5a,
          0x5a, 0x42, 0x54, 0x67, 0x53, 0x6d, 0x72, 0x57, 0x44, 0x74, 0x5a, 0x72, 0x6e, 0x2f, 0x69, 0x6d,
          0x0a, 0x69, 0x48, 0x34, 0x50, 0x49, 0x59, 0x51, 0x38, 0x75, 0x33, 0x73, 0x61, 0x46, 0x61, 0x42,
          0x74, 0x4f, 0x78, 0x6b, 0x62, 0x33, 0x62, 0x4a, 0x6b, 0x61, 0x30, 0x58, 0x78, 0x73, 0x70, 0x39,
          0x57, 0x4c, 0x34, 0x51, 0x39, 0x37, 0x6f, 0x70, 0x71, 0x77, 0x36, 0x52, 0x50, 0x58, 0x74, 0x43,
          0x72, 0x4d, 0x5a, 0x45, 0x66, 0x6f, 0x78, 0x6d, 0x35, 0x65, 0x50, 0x47, 0x41, 0x39, 0x31, 0x4a,
          0x2f, 0x0a, 0x43, 0x31, 0x6f, 0x6b, 0x52, 0x53, 0x48, 0x62, 0x70, 0x68, 0x67, 0x31, 0x4d, 0x4e,
          0x38, 0x6b, 0x37, 0x51, 0x4a, 0x42, 0x41, 0x50, 0x43, 0x47, 0x73, 0x53, 0x35, 0x6c, 0x51, 0x79,
          0x72, 0x52, 0x78, 0x6f, 0x55, 0x4d, 0x66, 0x67, 0x63, 0x77, 0x71, 0x72, 0x77, 0x6b, 0x64, 0x70,
          0x64, 0x37, 0x76, 0x65, 0x6d, 0x6b, 0x70, 0x6d, 0x2b, 0x65, 0x54, 0x47, 0x51, 0x48, 0x47, 0x61,
          0x67, 0x4f, 0x0a, 0x67, 0x71, 0x70, 0x62, 0x33, 0x53, 0x64, 0x47, 0x79, 0x76, 0x56, 0x69, 0x57,
          0x44, 0x71, 0x2f, 0x46, 0x58, 0x65, 0x76, 0x52, 0x6a, 0x59, 0x68, 0x77, 0x73, 0x6c, 0x74, 0x73,
          0x30, 0x2f, 0x48, 0x66, 0x43, 0x49, 0x32, 0x57, 0x71, 0x44, 0x47, 0x2b, 0x51, 0x38, 0x43, 0x51,
          0x51, 0x44, 0x4d, 0x53, 0x31, 0x6d, 0x4b, 0x37, 0x6d, 0x61, 0x56, 0x33, 0x72, 0x47, 0x44, 0x4b,
          0x49, 0x78, 0x65, 0x0a, 0x73, 0x38, 0x48, 0x46, 0x32, 0x7a, 0x63, 0x64, 0x6b, 0x51, 0x78, 0x6a,
          0x50, 0x48, 0x37, 0x74, 0x2b, 0x36, 0x6a, 0x35, 0x30, 0x52, 0x56, 0x68, 0x4c, 0x74, 0x6e, 0x37,
          0x49, 0x2b, 0x38, 0x6b, 0x59, 0x57, 0x73, 0x38, 0x4d, 0x42, 0x4a, 0x56, 0x34, 0x35, 0x51, 0x6e,
          0x67, 0x31, 0x34, 0x7a, 0x6f, 0x70, 0x53, 0x2b, 0x69, 0x4d, 0x76, 0x36, 0x2f, 0x42, 0x6d, 0x4f,
          0x51, 0x7a, 0x58, 0x32, 0x0a, 0x6c, 0x49, 0x54, 0x48, 0x41, 0x6b, 0x42, 0x42, 0x31, 0x49, 0x75,
          0x50, 0x36, 0x44, 0x55, 0x75, 0x39, 0x67, 0x56, 0x41, 0x69, 0x76, 0x2b, 0x2f, 0x56, 0x67, 0x6d,
          0x55, 0x76, 0x75, 0x49, 0x61, 0x61, 0x63, 0x71, 0x37, 0x74, 0x4d, 0x32, 0x38, 0x78, 0x50, 0x57,
          0x68, 0x64, 0x76, 0x51, 0x46, 0x74, 0x42, 0x72, 0x39, 0x4a, 0x33, 0x46, 0x71, 0x2b, 0x34, 0x77,
          0x33, 0x42, 0x76, 0x69, 0x67, 0x0a, 0x38, 0x34, 0x57, 0x62, 0x6f, 0x55, 0x51, 0x31, 0x4d, 0x70,
          0x35, 0x4f, 0x5a, 0x52, 0x44, 0x72, 0x70, 0x2b, 0x79, 0x49, 0x72, 0x4a, 0x6d, 0x33, 0x59, 0x56,
          0x33, 0x76, 0x41, 0x6b, 0x45, 0x41, 0x72, 0x71, 0x4a, 0x43, 0x6d, 0x75, 0x61, 0x4c, 0x76, 0x74,
          0x55, 0x73, 0x66, 0x4f, 0x65, 0x75, 0x68, 0x6b, 0x32, 0x32, 0x2b, 0x4d, 0x45, 0x5a, 0x62, 0x69,
          0x62, 0x4e, 0x70, 0x67, 0x37, 0x53, 0x0a, 0x6d, 0x66, 0x43, 0x6b, 0x55, 0x31, 0x69, 0x4e, 0x70,
          0x42, 0x4e, 0x2b, 0x74, 0x70, 0x58, 0x54, 0x47, 0x52, 0x42, 0x46, 0x73, 0x4a, 0x2b, 0x50, 0x4c,
          0x4f, 0x68, 0x72, 0x66, 0x78, 0x4e, 0x6d, 0x39, 0x56, 0x43, 0x6e, 0x51, 0x66, 0x43, 0x43, 0x48,
          0x62, 0x78, 0x65, 0x78, 0x43, 0x4e, 0x6a, 0x2f, 0x37, 0x4b, 0x5a, 0x68, 0x51, 0x4a, 0x41, 0x43,
          0x53, 0x75, 0x73, 0x74, 0x35, 0x44, 0x4a, 0x0a, 0x47, 0x7a, 0x69, 0x33, 0x44, 0x66, 0x31, 0x48,
          0x49, 0x77, 0x4d, 0x75, 0x46, 0x36, 0x78, 0x4a, 0x76, 0x4a, 0x75, 0x49, 0x68, 0x68, 0x78, 0x44,
          0x75, 0x37, 0x31, 0x6e, 0x6e, 0x55, 0x72, 0x2f, 0x46, 0x55, 0x54, 0x31, 0x53, 0x76, 0x77, 0x78,
          0x65, 0x4c, 0x6c, 0x70, 0x68, 0x57, 0x58, 0x68, 0x50, 0x4f, 0x77, 0x69, 0x6f, 0x66, 0x74, 0x6c,
          0x4c, 0x70, 0x4f, 0x59, 0x77, 0x45, 0x4f, 0x73, 0x0a, 0x72, 0x66, 0x62, 0x41, 0x72, 0x62, 0x66,
          0x75, 0x70, 0x66, 0x47, 0x6a, 0x34, 0x51, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45,
          0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d,
          0x2d, 0x2d, 0x2d, 0x0a
        ]
    }
    
    
    struct RSA_4096_PRIVATE_ENCRYPTED_PAIR {
        /// An unencrypted RSA 4096 Private Key
        ///
        /// Generated with
        /// ```
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:1024
        ///   -pkeyopt rsa_keygen_pubexp:65537
        ///   -out foo.pem
        /// ```
        static let UNENCRYPTED = """
        -----BEGIN PRIVATE KEY-----
        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
        MMr/ip29FfxUQTxaN5Y2QyCtq9TbvQ==
        -----END PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:mypassword
        /// ```
        static let ENCRYPTED_MYPASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        LpVBaO3pAvbSuwk63D0qvtn/dA==
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:
        /// ```
        static let ENCRYPTED_EMPTY_PASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        jyq8O7j2TX69oOv9398Z9zxPyg==
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-128-cbc
        ///     -passout pass:🔐
        /// ```
        static let ENCRYPTED_EMOJI_PASSWORD = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        qzfrTR18AMb1EaMKCHAXulhKwA==
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        /// The encrypted version of the RSA 1024 Private Key
        ///
        /// Encrypted with
        /// ```
        /// openssl pkcs8
        ///     -in foo.pem
        ///     -topk8
        ///     -v2 aes-256-cbc
        ///     -passout pass:mypassword
        /// ```
        static let ENCRYPTED_MYPASSWORD_AES_256_CBC = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        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
        A70rQAke/pza+pxGglhTeGA4lg==
        -----END ENCRYPTED PRIVATE KEY-----
        """
    }
    
    
}
