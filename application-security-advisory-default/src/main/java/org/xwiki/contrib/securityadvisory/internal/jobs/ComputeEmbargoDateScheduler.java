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
package org.xwiki.contrib.securityadvisory.internal.jobs;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.internal.VersionReleasedManager;

@Component(roles = ComputeEmbargoDateScheduler.class)
@Singleton
public class ComputeEmbargoDateScheduler
{
    private static final int EMBARGO_MONTH_DURATION = 3;

    @Inject
    private VersionReleasedManager versionReleasedManager;

    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    private Date computeEmbargoDate(Date latestDate)
    {
        return Date.from(latestDate.toInstant().plus(EMBARGO_MONTH_DURATION, ChronoUnit.MONTHS));
    }

    private Date getLatestDate(List<Date> dateList) {
        Collections.sort(dateList);
        return dateList.get(dateList.size() - 1);
    }

    private List<Date> getVersionsDates(List<String> versions)
    {
        List<Date> result = new ArrayList<>();
        for (String version : versions) {
            result.add(this.versionReleasedManager.getReleaseDate(version));
        }
        return result;
    }

    private Date computeEmbargoDate(List<String> versions)
    {
        Date result = null;
        List<Date> releaseDates = new ArrayList<>();
        for (String version : versions) {
            if (this.versionReleasedManager.isVersionReleased(version)) {
                releaseDates.add(this.versionReleasedManager.getReleaseDate(version));
            } else {
                break;
            }
        }
        if (versions.size() == releaseDates.size()) {
            Date latestDate = getLatestDate(releaseDates);
            result = this.computeEmbargoDate(latestDate);
        }

        return result;
    }

    public void computeEmbargoDates()
    {
        List<SecurityAdvisory> advisories = this.securityAdvisoriesManager.getAdvisoriesWithStatus("announced", true);
        for (SecurityAdvisory advisory : advisories) {
            Date embargoDate = this.computeEmbargoDate(advisory.getPatchedVersions());
            if (embargoDate != null) {
                advisory.setEmbargoDate(embargoDate);
                this.securityAdvisoriesManager.saveEmbargoDate(advisory);

                // TODO: trigger a notification
            }
        }
    }
}
