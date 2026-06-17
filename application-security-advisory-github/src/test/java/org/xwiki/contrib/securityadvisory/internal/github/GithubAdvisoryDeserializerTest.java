package org.xwiki.contrib.securityadvisory.internal.github;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
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
    void deserializeTest() throws IOException, org.xwiki.contrib.securityadvisory.SecurityAdvisoryException
    {
        when(configuration.getSecurityDataSpace()).thenReturn(new SpaceReference("xwiki", "Security", "Data"));
        String testJson = IOUtils.resourceToString("examples.json", Charset.defaultCharset(),
            GithubAdvisoryDeserializerTest.class.getClassLoader());
        List<SecurityAdvisory> advisoryList = new ArrayList<>();
        deserializer.processGithubResponse("xwiki", testJson, advisoryList);

        // FIXME: build the list for comparison
        List<SecurityAdvisory> expected = new ArrayList<>();
        assertEquals(3, advisoryList.size());
    }

    @Test
    void testRangeConversion() throws org.xwiki.contrib.securityadvisory.SecurityAdvisoryException
    {
        when(configuration.getSecurityDataSpace()).thenReturn(new SpaceReference("xwiki", "Security", "Data"));

        // Case 1: Double bound
        assertRangeConversion(">= 1.0.0, < 2.0.0", List.of("[1.0.0,2.0.0)"));

        // Case 2: Single lower bound inclusive
        assertRangeConversion(">= 1.0.0", List.of("[1.0.0,)"));

        // Case 3: Single lower bound exclusive
        assertRangeConversion("> 1.0.0", List.of("(1.0.0,)"));

        // Case 4: Single upper bound inclusive.
        assertRangeConversion("<= 1.0.0", List.of("(,1.0.0]"));

        // Case 5: Single upper bound exclusive.
        assertRangeConversion("< 1.0.0", List.of("(,1.0.0)"));

        // Case 6: Equality
        assertRangeConversion("= 1.0.0", List.of("[1.0.0]"));

        // Case 7: Non-standard range (fallback)
        assertRangeConversion("[7.2 - 11.10.2]", List.of("[7.2 - 11.10.2]"));

        // Case 8: Multiple ranges (as seen in examples.json)
        assertRangeConversion(">= 11.3.7, >= 12.0RC1, >= 11.10.3",
            List.of("[11.3.7,)", "[12.0RC1,)", "[11.10.3,)"));
    }

    private void assertRangeConversion(String githubRange, List<String> expectedMavenRanges)
        throws org.xwiki.contrib.securityadvisory.SecurityAdvisoryException
    {
        String testJson = "[" +
            "  {" +
            "    \"ghsa_id\": \"GHSA-test\"," +
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
        deserializer.processGithubResponse("xwiki", testJson, advisoryList);

        assertEquals(1, advisoryList.size());
        SecurityAdvisory advisory = advisoryList.get(0);
        List<String> actual = advisory.getVulnerablePackages().get(0).affectedVersionsRanges();
        assertEquals(expectedMavenRanges, actual);
    }
}