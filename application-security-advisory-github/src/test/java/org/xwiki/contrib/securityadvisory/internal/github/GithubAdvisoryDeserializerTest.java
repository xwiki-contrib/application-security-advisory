/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.securityadvisory.internal.github;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ComponentTest
class GithubAdvisoryDeserializerTest
{
    @InjectMockComponents
    private GithubAdvisoryDeserializer deserializer;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @Test
    void deserializeTest() throws IOException, SecurityAdvisoryException
    {
        when(configuration.getSecurityDataSpace()).thenReturn(new SpaceReference("xwiki", "Security", "Data"));
        String testJson = IOUtils.resourceToString("examples.json", Charset.defaultCharset(),
            GithubAdvisoryDeserializerTest.class.getClassLoader());
        List<SecurityAdvisory> advisoryList = new ArrayList<>();
        deserializer.processGithubResponse(new Date(0), testJson, false, advisoryList);

        // FIXME: build the list for comparison
        List<SecurityAdvisory> expected = new ArrayList<>();
        assertEquals(3, advisoryList.size());
    }

    @ParameterizedTest
    @CsvSource({
        "'>= 1.0.0, < 2.0.0', '[1.0.0,2.0.0)'",
        "'> 1.0.0, <= 2.0.0', '(1.0.0,2.0.0]'",
        "'>= 1.0.0', '[1.0.0,)'",
        "'> 1.0.0', '(1.0.0,)'",
        "'<= 1.0.0', '(,1.0.0]'",
        "'< 1.0.0', '(,1.0.0)'",
        "'= 1.0.0', '[1.0.0]'",
        "'[7.2 - 11.10.2]', '[7.2 - 11.10.2]'"
    })
    void testRangeConversion(String githubRange, String expectedMavenRange) throws SecurityAdvisoryException
    {
        when(configuration.getSecurityDataSpace()).thenReturn(new SpaceReference("xwiki", "Security", "Data"));

        assertRangeConversion(githubRange, List.of(expectedMavenRange));
    }

    @Test
    void testMultipleRangesConversion() throws SecurityAdvisoryException
    {
        when(configuration.getSecurityDataSpace()).thenReturn(new SpaceReference("xwiki", "Security", "Data"));

        // Invalid but used in practice.
        assertRangeConversion(">= 11.3.7, >= 12.0RC1, >= 11.10.3",
            List.of("[11.3.7,)", "[12.0RC1,)", "[11.10.3,)"));
    }

    private void assertRangeConversion(String githubRange, List<String> expectedMavenRanges)
        throws SecurityAdvisoryException
    {
        String testJson = "[" +
            "  {" +
            "    \"ghsa_id\": \"GHSA-test\"," +
            "    \"html_url\": \"https://github.com/xwiki/xwiki-platform/GHSA-test\"," +
            "    \"updated_at\": \"2025-06-12T07:31:10Z\"," +
            "    \"state\": \"published\"," +
            "    \"vulnerabilities\": [" +
            "      {" +
            "        \"package\": {\"ecosystem\": \"maven\", \"name\": \"group:artifact\"}," +
            "        \"vulnerable_version_range\": \"" + githubRange + "\"," +
            "        \"patched_versions\": \"2.0.0\"" +
            "      }" +
            "    ]" +
            "  }" +
            "]";
        List<SecurityAdvisory> advisoryList = new ArrayList<>();
        deserializer.processGithubResponse(new Date(0), testJson, false, advisoryList);

        assertEquals(1, advisoryList.size());
        SecurityAdvisory advisory = advisoryList.get(0);
        List<String> actual = advisory.getVulnerablePackages().get(0).affectedVersionsRanges();
        assertEquals(expectedMavenRanges, actual);
    }
}