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

package com.commonsware.cwac.netsecurity.test;

import android.support.test.runner.AndroidJUnit4;

import com.commonsware.cwac.netsecurity.OkHttp3Integrator;
import com.commonsware.cwac.netsecurity.TrustManagerBuilder;

import junit.framework.Assert;
import junit.framework.AssertionFailedError;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@RunWith(AndroidJUnit4.class)
abstract public class AbstractOkHttp3TestV2 {

    abstract protected String getUrl();

    abstract protected TrustManagerBuilder getBuilder() throws Exception;

    abstract protected SSLSocketFactory getSSLSocketFactory() throws Exception;

    @SuppressWarnings("ConstantConditions")
    @Test
    public void testRequest() throws Exception {

        test();
        test();
        test();
        test();
    }

    private void test() throws Exception {
        final Request request = new Request.Builder()
                .url(getUrl())
                .build();


        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder();

            final TrustManagerBuilder tmb = getBuilder();
            if (tmb != null) {
                OkHttp3Integrator.applyTo(tmb, builder);
            }

            doExecute(request, builder);
            doExecute(request, builder);
        } catch (SSLHandshakeException e) {
            if (isPositiveTest()) {
                throw e;
            }
        } catch (RuntimeException e) {
            if (isPositiveTest() ||
                    !e.getClass().getSimpleName().equals("CleartextAttemptException")) {
                throw e;
            }
        }
    }

    private void doExecute(Request request, OkHttpClient.Builder builder) throws Exception {


        SSLSocketFactory sslSocketFactory = getSSLSocketFactory();
        if (sslSocketFactory != null) {
            builder.sslSocketFactory(sslSocketFactory, construct());
        }


        Response response = builder.build().newCall(request).execute();
        if (!isPositiveTest()) {
            throw new AssertionFailedError("Expected SSLHandshakeException, did not get!");
        }
        Assert.assertEquals(getExpectedResponse(), response.body().string());
    }

    public abstract X509TrustManager construct() throws NoSuchAlgorithmException, KeyStoreException;


    protected String getExpectedResponse() {
        return ("{\"Hello\": \"world\"}");
    }

    protected boolean isPositiveTest() {
        return (true);
    }
}
