/***
 Copyright (c) 2016 CommonsWare, LLC
 Licensed under the Apache License, Version 2.0 (the "License"); you may not
 use this file except in compliance with the License. You may obtain a copy
 of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required
 by applicable law or agreed to in writing, software distributed under the
 License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 OF ANY KIND, either express or implied. See the License for the specific
 language governing permissions and limitations under the License.
 */

package com.commonsware.cwac.netsecurity.test.client.certificate;

import android.support.annotation.NonNull;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.commonsware.cwac.netsecurity.OkHttp3Integrator;
import com.commonsware.cwac.netsecurity.TrustManagerBuilder;

import junit.framework.Assert;
import junit.framework.AssertionFailedError;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@RunWith(AndroidJUnit4.class)
public class ClientCertificateTest {

    private TrustManagerBuilder trustManagerBuilder;
    private X509TrustManager trustManager;
    private KeyManager[] keyManagers;

    protected String getUrl() {
        return ("https://env-53982.customer.cloud.microstrategy.com:3443/org/orgbasicinfo/2");
    }

    protected TrustManagerBuilder getTrustManagerBuilder() {

        if (trustManagerBuilder == null) {
            trustManagerBuilder = new TrustManagerBuilder().withManifestConfig(InstrumentationRegistry.getContext());
        }
        return trustManagerBuilder;
    }


    public X509TrustManager constructTrustManager() throws NoSuchAlgorithmException, KeyStoreException {

        if (trustManager == null) {
            trustManager = getTrustManager();
        }
        return trustManager;

    }

    private X509TrustManager getTrustManager() throws NoSuchAlgorithmException, KeyStoreException {

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new IllegalStateException("Unexpected default trust managers:"
                    + Arrays.toString(trustManagers));
        }

        return (X509TrustManager) trustManagers[0];
    }

    protected SSLSocketFactory getSSLSocketFactory() throws Exception {


        try {
            //have to create a new ssl socket factory.
            return getSslSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SSLSocketFactory getSslSocketFactory() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers(), new X509TrustManager[]{constructTrustManager()}, null);
        return sslContext.getSocketFactory();
    }

    protected KeyManager[] keyManagers() throws Exception {

        try {
            if (keyManagers == null) {
                keyManagers = getKeyManagers();
            }
            return keyManagers;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private KeyManager[] getKeyManagers() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        KeyStore keyStore = provideKeyStore();
        kmf.init(keyStore, "13".toCharArray());
        return kmf.getKeyManagers();
    }


    private KeyStore provideKeyStore() {

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(InstrumentationRegistry.getContext().getAssets().open("cert.p12"), "123".toCharArray());
            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return null;

    }

    protected String getExpectedResponse() {
        return ("{\"org_requires_login\":false,\"org_name\":\"Usher_Benchmark_2\"}");
    }


    @SuppressWarnings("ConstantConditions")
    @Test
    public void testRequest() throws Exception {

        OkHttpClient.Builder builder = getBuilder();
        test(builder);
        test(builder);
        test(builder);
        test(builder);
    }

    private void test(OkHttpClient.Builder builder) throws Exception {
        final Request request = new Request.Builder().url(getUrl()).build();
        try {
            builder.sslSocketFactory(getSSLSocketFactory(), constructTrustManager());
            doExecute(request, builder.build());
        } catch (SSLHandshakeException e) {
            if (isPositiveTest()) {
                throw e;
            }
        } catch (RuntimeException e) {
            if (isPositiveTest() || !e.getClass().getSimpleName().equals("CleartextAttemptException")) {
                throw e;
            }
        }
    }

    @NonNull
    private OkHttpClient.Builder getBuilder() throws Exception {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        OkHttp3Integrator.applyTo(getTrustManagerBuilder(), builder);
        return builder;
    }

    private void doExecute(Request request, OkHttpClient okHttpClient) throws Exception {
        Response response = okHttpClient.newCall(request).execute();
        if (!isPositiveTest()) {
            throw new AssertionFailedError("Expected SSLHandshakeException, did not get!");
        }
        //noinspection ConstantConditions
        Assert.assertEquals(getExpectedResponse(), response.body().string());
    }

    protected boolean isPositiveTest() {
        return (true);
    }
}
