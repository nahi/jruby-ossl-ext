/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2010 Hiroshi Nakamura <nahi@ruby-lang.org>
 * 
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:nahi@ruby-lang.org">Hiroshi Nakamura</a>
 */
public class SSLSession extends RubyObject {
    private static ObjectAllocator SSLSESSION_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLSession(runtime, klass);
        }
    };

    public static void createSSLSession(Ruby runtime, RubyModule mOSSL) {
        RubyModule mSSL = mOSSL.defineModuleUnder("SSL");
        RubyClass cSSLSession = mSSL.defineClassUnder("Session", runtime.getObject(),
                SSLSESSION_ALLOCATOR);
        RubyClass eOSSLError = mOSSL.getClass("OpenSSLError");
        cSSLSession.defineClassUnder("SessionError", eOSSLError, eOSSLError.getAllocator());
        cSSLSession.defineAnnotatedMethods(SSLSession.class);
    }

    public SSLSession(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    @JRubyMethod(required = 1, frame = true)
    public IRubyObject initialize(ThreadContext ctx, IRubyObject arg) {
        return this;
    }

    @JRubyMethod(name = "==", required = 1)
    public IRubyObject eq(ThreadContext ctx, IRubyObject rhs) {
        // TODO: implement
        return getRuntime().getFalse();
    }

    @JRubyMethod(required = 0)
    public IRubyObject time() {
        // TODO: implement
        return getRuntime().getNil();
    }

    @JRubyMethod(name = "time=", required = 1)
    public IRubyObject set_time(ThreadContext ctx, IRubyObject rhs) {
        // TODO: implement
        return rhs;
    }

    @JRubyMethod(required = 0)
    public IRubyObject timeout() {
        // TODO: implement
        return getRuntime().getNil();
    }

    @JRubyMethod(name = "timeout=", required = 1)
    public IRubyObject set_timeout(ThreadContext ctx, IRubyObject rhs) {
        // TODO: implement
        return rhs;
    }

    @JRubyMethod(required = 0)
    public IRubyObject id() {
        // TODO: implement
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject to_der() {
        // TODO: implement
        return getRuntime().getNil();
    }

    @JRubyMethod(name = { "to_pem", "to_s" })
    public IRubyObject to_pem() {
        // TODO: implement
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject to_text() {
        // TODO: implement
        return getRuntime().getNil();
    }
}
