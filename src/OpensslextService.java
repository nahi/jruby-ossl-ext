/*****
 * BEGIN LICENSE BLOCK ***** Version: CPL 1.0/GPL 2.0/LGPL 2.1 The contents of
 * this file are subject to the Common Public License Version 1.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.eclipse.org/legal/cpl-v10.html Software distributed under the
 * License is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing rights and limitations under the License. Copyright (C) 2007 Ola
 * Bini <ola@ologix.com> Alternatively, the contents of this file may be used
 * under the terms of either of the GNU General Public License Version 2 or
 * later (the "GPL"), or the GNU Lesser General Public License Version 2.1 or
 * later (the "LGPL"), in which case the provisions of the GPL or the LGPL are
 * applicable instead of those above. If you wish to allow use of your version
 * of this file only under the terms of either the GPL or the LGPL, and not to
 * allow others to use your version of this file under the terms of the CPL,
 * indicate your decision by deleting the provisions above and replace them with
 * the notice and other provisions required by the GPL or the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under the terms of any one of the CPL, the GPL or the LGPL. END LICENSE
 * BLOCK
 *****/

import java.io.IOException;

import org.jruby.Ruby;
import org.jruby.RubyModule;
import org.jruby.ext.openssl.ASN1;
import org.jruby.ext.openssl.NetscapeSPKI;
import org.jruby.ext.openssl.OpenSSLReal;
import org.jruby.ext.openssl.PKCS7;
import org.jruby.ext.openssl.SSL;
import org.jruby.ext.openssl.X509;
import org.jruby.ext.openssl.x509store.BouncyCastleASN1FormatHandler;
import org.jruby.runtime.load.BasicLibraryService;

public class OpensslextService implements BasicLibraryService {
    @Override
    public boolean basicLoad(Ruby runtime) throws IOException {
        RubyModule ossl = runtime.getModule("OpenSSL");
        try {
            OpenSSLReal.setFormatHandler(new BouncyCastleASN1FormatHandler());
            OpenSSLReal.setBCProvider((java.security.Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance());
            ASN1.createASN1(runtime, ossl);
            X509.createX509(runtime, ossl);
            NetscapeSPKI.createNetscapeSPKI(runtime, ossl);
            PKCS7.createPKCS7(runtime, ossl);
        } catch (ClassNotFoundException ignore) {
            // no bc*.jar
            runtime.getLoadService().require("openssl/dummy");
        } catch (IllegalAccessException ignore) {
            runtime.getLoadService().require("openssl/dummy");
        } catch (InstantiationException ignore) {
            runtime.getLoadService().require("openssl/dummy");
        } catch (SecurityException ignore) {
            // some class might be prohibited to use.
            runtime.getLoadService().require("openssl/dummy");
        } catch (Error ignore) {
            // mainly for rescuing NoClassDefFoundError: no bc*.jar
            runtime.getLoadService().require("openssl/dummy");
        }
        try {
            SSL.createSSL(runtime, ossl);
        } catch (SecurityException ignore) {
            // some class might be prohibited to use. ex. SSL* on GAE/J.
            runtime.getLoadService().require("openssl/dummyssl");
        } catch (Error ignore) {
            // mainly for rescuing NoClassDefFoundError: no bc*.jar
            runtime.getLoadService().require("openssl/dummyssl");
        }
        return true;
    }
}
