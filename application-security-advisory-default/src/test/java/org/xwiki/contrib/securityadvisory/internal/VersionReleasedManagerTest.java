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
package org.xwiki.contrib.securityadvisory.internal;

import java.text.DateFormat;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ComponentTest
class VersionReleasedManagerTest
{
    @InjectMockComponents
    private VersionReleasedManager versionReleasedManager;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @Test
    void computeEmbargoDate() throws ParseException
    {
        Date latestDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/12/2022 11:00:00");

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);

        Date expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("24/12/2022 11:00:00");
        Date obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.MINUTES);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(10L);

        expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/12/2022 11:10:00");
        obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.MONTHS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(1L);

        expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/01/2023 11:00:00");
        obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);
    }
}