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

package com.commonsware.cwac.netsecurity.test.priv.okhttp3;

import com.commonsware.cwac.netsecurity.TrustManagerBuilder;
import com.commonsware.cwac.netsecurity.test.AbstractOkHttp3Test;

public class NonCsrHTTPSTest extends AbstractOkHttp3Test {
  @Override
  protected String getUrl() {
    return("https://mstr-1w.customer.cloud.microstrategy.com/org/orgbasicinfo/15064");
  }

  @Override
  protected TrustManagerBuilder getBuilder() {
    return(null);
  }

  protected String getExpectedResponse() {
    return("{\"org_requires_login\":true,\"org_name\":\"MicroStrategy, Inc.\"}");
  }


}
