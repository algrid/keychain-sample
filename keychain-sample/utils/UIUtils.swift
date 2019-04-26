//
//  UIUtils.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 4/25/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import UIKit

extension UILabel {
    public func setTextWithAlphaAnimation(_ str: String?) {
        text = str
        alpha = 0.0
        UIView.animate(withDuration: 1.0) {
            self.alpha = 1.0
        }
    }
}

extension UIAlertController {
    public static func showSimple(title: String?, text: String?, from vc: UIViewController) {
        let alert = UIAlertController(title: title, message: text, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        vc.present(alert, animated: true, completion: nil)
    }
}
