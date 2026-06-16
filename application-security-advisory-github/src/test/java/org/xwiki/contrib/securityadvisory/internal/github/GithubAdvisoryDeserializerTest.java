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
}