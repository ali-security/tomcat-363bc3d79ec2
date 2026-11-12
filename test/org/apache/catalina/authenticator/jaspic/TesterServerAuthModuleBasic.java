/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.authenticator.jaspic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Minimal BASIC style {@link ServerAuthModule} that validates the supplied credentials using the
 * {@link PasswordValidationCallback} and therefore the Realm associated with the {@link CallbackHandler} provided when
 * the module was initialised.
 */
public class TesterServerAuthModuleBasic implements ServerAuthModule {

    private static final String BASIC_PREFIX = "Basic ";

    private CallbackHandler handler;

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
            @SuppressWarnings("rawtypes") Map options) throws AuthException {
        this.handler = handler;
    }


    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
            throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        String authorization = request.getHeader("Authorization");
        if (authorization != null &&
                authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            String decoded = new String(
                    Base64.getDecoder().decode(authorization.substring(BASIC_PREFIX.length()).trim()),
                    StandardCharsets.ISO_8859_1);
            int colon = decoded.indexOf(':');
            if (colon > 0) {
                PasswordValidationCallback pvc = new PasswordValidationCallback(clientSubject,
                        decoded.substring(0, colon), decoded.substring(colon + 1).toCharArray());
                try {
                    handler.handle(new Callback[] { pvc });
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new AuthException(e);
                }
                if (pvc.getResult()) {
                    return AuthStatus.SUCCESS;
                }
            }
        }

        response.setHeader("WWW-Authenticate", "Basic realm=\"jaspic\"");
        try {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IOException e) {
            throw new AuthException(e);
        }
        return AuthStatus.SEND_CONTINUE;
    }


    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }


    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        // NO-OP
    }


    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return new Class<?>[] { HttpServletRequest.class, HttpServletResponse.class };
    }
}
