//
//  Utils.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 4/25/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import Foundation

extension Data {
    public func toHexString() -> String {
        return reduce("", {$0 + String(format: "%02X ", $1)})
    }
}
