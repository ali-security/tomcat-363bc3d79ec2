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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/*
 * When a single SimpleAuthConfigProvider is registered as the default provider it is used by every web application.
 * The ServerAuthConfig (and hence the CallbackHandler and Realm) must not be shared between those web applications.
 */
public class TestSimpleAuthConfigProvider extends TomcatBaseTest {

    private static final String SERVER_AUTH_MODULE_KEY = "org.apache.catalina.authenticator.jaspic.ServerAuthModule.1";

    private static final String ROLE = "role";

    private static final String CONTEXT_A = "/a";
    private static final String USER_A = "userA";
    private static final String PWD_A = "passwordA";

    private static final String CONTEXT_B = "/b";
    private static final String USER_B = "userB";
    private static final String PWD_B = "passwordB";


    @Test
    public void testServerAuthConfigNotSharedBetweenAppContexts() throws Exception {
        Map<String,Object> properties = new HashMap<>();
        properties.put(SERVER_AUTH_MODULE_KEY, TesterServerAuthModuleBasic.class.getName());
        SimpleAuthConfigProvider provider = new SimpleAuthConfigProvider(properties, null);

        ServerAuthConfig configA =
                provider.getServerAuthConfig("HttpServlet", "localhost " + CONTEXT_A, new CallbackHandlerImpl());
        ServerAuthConfig configB =
                provider.getServerAuthConfig("HttpServlet", "localhost " + CONTEXT_B, new CallbackHandlerImpl());

        Assert.assertNotSame(configA, configB);
        Assert.assertEquals("localhost " + CONTEXT_A, configA.getAppContext());
        Assert.assertEquals("localhost " + CONTEXT_B, configB.getAppContext());
    }


    @Test
    public void testRealmNotSharedBetweenWebApplications() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        addContext(tomcat, CONTEXT_A, USER_A, PWD_A);
        addContext(tomcat, CONTEXT_B, USER_B, PWD_B);

        // Single SimpleAuthConfigProvider registered as the default provider for all web applications
        Map<String,Object> properties = new HashMap<>();
        properties.put(SERVER_AUTH_MODULE_KEY, TesterServerAuthModuleBasic.class.getName());
        SimpleAuthConfigProvider provider = new SimpleAuthConfigProvider(properties, null);
        AuthConfigFactory factory = AuthConfigFactory.getFactory();
        String registrationId = factory.registerConfigProvider(provider, null, null, "Test default provider");

        try {
            tomcat.start();

            // First web application to authenticate a request
            doRequest(CONTEXT_A, USER_A, PWD_A, HttpServletResponse.SC_OK);

            // Credentials for the first web application must not be accepted by the second
            doRequest(CONTEXT_B, USER_A, PWD_A, HttpServletResponse.SC_UNAUTHORIZED);

            // The second web application must use its own Realm
            doRequest(CONTEXT_B, USER_B, PWD_B, HttpServletResponse.SC_OK);

            // And the first web application must continue to use its own Realm
            doRequest(CONTEXT_A, USER_B, PWD_B, HttpServletResponse.SC_UNAUTHORIZED);
            doRequest(CONTEXT_A, USER_A, PWD_A, HttpServletResponse.SC_OK);
        } finally {
            factory.removeRegistration(registrationId);
        }
    }


    private static void addContext(Tomcat tomcat, String contextPath, String user, String password) {
        Context ctx = tomcat.addContext(contextPath, null);

        Tomcat.addServlet(ctx, "TesterServlet", new TesterServlet());
        ctx.addServletMappingDecoded("/*", "TesterServlet");

        SecurityCollection collection = new SecurityCollection();
        collection.addPatternDecoded("/*");
        SecurityConstraint constraint = new SecurityConstraint();
        constraint.addAuthRole(ROLE);
        constraint.addCollection(collection);
        ctx.addConstraint(constraint);

        // Each web application has its own Realm with a different user
        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser(user, password);
        realm.addUserRole(user, ROLE);
        ctx.setRealm(realm);

        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod("BASIC");
        ctx.setLoginConfig(lc);
        ctx.getPipeline().addValve(new BasicAuthenticator());
    }


    private void doRequest(String contextPath, String user, String password, int expectedRC) throws Exception {
        Map<String,List<String>> reqHeaders = new HashMap<>();
        List<String> auth = new ArrayList<>();
        auth.add("Basic " +
                Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.ISO_8859_1)));
        reqHeaders.put("Authorization", auth);

        ByteChunk bc = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + contextPath + "/", bc, reqHeaders, null);

        Assert.assertEquals("Unexpected status for user [" + user + "] accessing [" + contextPath + "]", expectedRC,
                rc);
        if (expectedRC == HttpServletResponse.SC_OK) {
            Assert.assertEquals("OK", bc.toString());
        }
    }
}
