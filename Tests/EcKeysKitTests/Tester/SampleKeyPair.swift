import Foundation

struct KeyPair {
    let privateKey: Data
    let publicKey: Data
}

struct Sample {
    let der: KeyPair // From java.security @ JDK 1.8.0_66
    let x963: KeyPair // From Security @ iOS 10.0
    
    init(derPrivate: String, derPublic: String, x963Private: String, x963Public: String) {
        self.der = .init(
            privateKey: Data(base64Encoded: derPrivate)!,
            publicKey: Data(base64Encoded: derPublic)!
        )
        self.x963 = .init(
            privateKey: Data(base64Encoded: x963Private)!,
            publicKey: Data(base64Encoded: x963Public)!
        )
    }
    
    static let p256r1 = Self(
        derPrivate: "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBfO6gA9UO14Q/8n0Gli1yzkrOXQJBEf3MQK4CRntI9PA==",
        derPublic: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLn0V/JKsIZtJMemzhb/KtoEfRfEAH74LQzE0w/Iju49WgEPmg5c+RQ4KXW1fzkCOXLJsRFGfhgCtBwrrvc7bw==",
        x963Private: "BJuqMJR8R9kUiB9X9rGbxslANAwOxosqokkBOH+7s/WgFVBcZIRP8HiG4+93gp5ft7iHYgs8C1AVem0+LbCsDDqhu4GppkNWUlOs7wCJGdCbl/X40vvOhxmZmNaGsFFKkQ==",
        x963Public: "BJuqMJR8R9kUiB9X9rGbxslANAwOxosqokkBOH+7s/WgFVBcZIRP8HiG4+93gp5ft7iHYgs8C1AVem0+LbCsDDo="
    )
    
    static let p384r1 = Self(
        derPrivate: "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDC4I1ybNLii81F1LS9B1SdhxBPPMr7L0ejKqKXw32gURRuVWEsjF+gN6nFoODwuKzU=",
        derPublic: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+kE+Fh8UwNXjyEuWCZnyG18e2OUUQ29iP8o4DPhpKdk56ODEd2YW3oJDzh+nLu/IPjCsJKk9DxsRKvaSoETA3xWFwGrKbj84lAtMgb0Qh3M2Cm8NhzBd2DR6RoGzaBi5",
        x963Private: "BNWb8kv405UxPa1bCTAh5NI0J7FBVsoGp5bCyd6j76IW7F7/rWSmJfO5EB930wzFk0QLd1TSTh40nxp0E9WtMR+q6RK0bWz7EnfATSMkMeYjJCkX+f8nqJyOhgpT883xHCVKTe1zvtqAVCE5FYzztMZcnCpVHSh4+6uMotwfEBM5+7881Jfjj2hHdemf0jImRw==",
        x963Public: "BNWb8kv405UxPa1bCTAh5NI0J7FBVsoGp5bCyd6j76IW7F7/rWSmJfO5EB930wzFk0QLd1TSTh40nxp0E9WtMR+q6RK0bWz7EnfATSMkMeYjJCkX+f8nqJyOhgpT883xHA=="
    )
    
    static let p521r1_64 = Self(
        derPrivate: "MF4CAQAwEAYHKoZIzj0CAQYFK4EEACMERzBFAgEBBEDR2wMItgTpi79zRHha4kjbd2WpnQFT4Ibn3uvRaCM4nwlg9XtzcpEV/24yJtI84A6gvARjeylZp4P1kzFOZWqF",
        derPublic: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBnHQEjDjHHzKGHchi71vlGtRttWZOGE9JPZzKg7owErt/imL1Yy4FC5EI6TYvJo5MY5+2lGgaDssjcEPjgwkjRAABMcMXUm8V+EXxupl6iciBhE9yOezlaU8tqGqDG1rkHWtehOsUbzgCJA0vzDTfeXXlG8GG4lG5rlQ58weDVSC8R70=",
        x963Private: "BACZJXprLScyU2K6G/lRLErCx4yEboUzS2ieu+UmLRDWKj/1u66KPuwuiqv8sth1RsgGVQKnwSUL0e+l9Ie6DPwUTgF5yJIbCIEVqRIE/CZOsQYR2nnsT+6i9j+PQSt6uvVBSMFgSHNH4fOzNuqgYBGsQ8QpjwWQtWXlCtBO6Fc/ahooFgFr5ehes+UDBTV8e1tXaNnj8SYW/lR07K4tQjn8hG+u84Z8hMDBkpBQ4dB06oAnhVc9QI4MdqpqjWH1w9d/ABrr3A==",
        x963Public: "BACZJXprLScyU2K6G/lRLErCx4yEboUzS2ieu+UmLRDWKj/1u66KPuwuiqv8sth1RsgGVQKnwSUL0e+l9Ie6DPwUTgF5yJIbCIEVqRIE/CZOsQYR2nnsT+6i9j+PQSt6uvVBSMFgSHNH4fOzNuqgYBGsQ8QpjwWQtWXlCtBO6Fc/ahooFg=="
    )
    
    static let p521r1_65 = Self(
        derPrivate: "MF8CAQAwEAYHKoZIzj0CAQYFK4EEACMESDBGAgEBBEGlOBiMll+fyspj6ejNIj8BTF3iHoTnWRssikGfPxQ6I3Tph2qUO3QR/rOWmYDCRQpkmElg4Io2Di2k/5rpUHZkGg==",
        derPublic: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBnqlFLb2+yC7kjP1h9zPr+2Elho8q2mef082FivAAP7X+XW3J74WITf5+bH6dxN922qyP23sBRJWeDwAxorC5PKcBJJMAAWBzsVr6wmizal7nWeNp3D0wtehFhtjH8JqIUO5RgLRlq/105kUSFoitTRWD0X8VZdLJBHfUKHcFTiOtBCo=",
        x963Private: "BACLHG3RO6aWdaYXA5MZTTL/Kv5nPNDLWCJ4OLPMhbXwbU135qaWcKTLQwH6X7qkMseyUEXs9eh4kJoWoRuqG5qfYQHppMDK9AaZEKOQUNQ7/kzQhbHS9kNlztVab1f0EAQz5VmLZYWu1K1ImML/sIVKLg3OAdLpN8dwIDi7kkRK7FZbdgA9ZhE60vGKXk4pmN4ZSJiFW+4Ny3ZOZgHTUskEjoTKgdxsn2f9C3xtADiyuZkkQj/YtdLLYW7TFi7jfZBEB613JA==",
        x963Public: "BACLHG3RO6aWdaYXA5MZTTL/Kv5nPNDLWCJ4OLPMhbXwbU135qaWcKTLQwH6X7qkMseyUEXs9eh4kJoWoRuqG5qfYQHppMDK9AaZEKOQUNQ7/kzQhbHS9kNlztVab1f0EAQz5VmLZYWu1K1ImML/sIVKLg3OAdLpN8dwIDi7kkRK7FZbdg=="
    )
    
    static let p521r1_66 = Self(
        derPrivate: "MGACAQAwEAYHKoZIzj0CAQYFK4EEACMESTBHAgEBBEIBgz1fdXJ1HqQN40OgKuqpyPRWQO8feUaGMd6fWFhl0GOZ6dEqiJ6HY07RtwTLLcvm3v14xCZHJJod8VK7f6dmw7w=",
        derPublic: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBK5LG03MuXoD2UY0G73opWBgpXT+18WllX+KrQMsB0wR8DW0wBX2vGu1CZ33VZEfkVY5c9lKigqrYlN39CyL8qKoBKT5JW/+LHnt8rhmYWlwaH34ZD7fVbsoCAyYn6CCmeSal6iUYBYpy0WtcA/cuWRFblhwNH7A1f/EvnpyBmMF0xK0=",
        x963Private: "BABMFUo7xnY4lc1zOd8H9TKMmvW1UEiREKo4vmkZkGD9X4sHF/gJQ/sGcUlViD9S3YZZ92eeqjrZV8XAc7gjhdxSMgFiadmHFrRFsNy60Lifsv6EmECEQlcuonT7iGqPldpY4+Mc+Mr67ptw/N5ZQX1mHH50FEls5k33MLJqxuxBB8lkeABILm9IjddWuma/wKyua/7AdwLtklIMO8jYiDdlaiYaeiOw2Qkk6TopxZbx3SINHMNQSFI/ishS38Aq1xZuHFq+2w==",
        x963Public: "BABMFUo7xnY4lc1zOd8H9TKMmvW1UEiREKo4vmkZkGD9X4sHF/gJQ/sGcUlViD9S3YZZ92eeqjrZV8XAc7gjhdxSMgFiadmHFrRFsNy60Lifsv6EmECEQlcuonT7iGqPldpY4+Mc+Mr67ptw/N5ZQX1mHH50FEls5k33MLJqxuxBB8lkeA=="
    )
}
