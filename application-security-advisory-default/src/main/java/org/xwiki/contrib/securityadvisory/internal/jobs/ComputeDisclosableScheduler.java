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

@Component(roles = ComputeDisclosableScheduler.class)
@Singleton
public class ComputeDisclosableScheduler
{
    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    public void computeDisclosable()
    {
        Date currentDate = new Date();
        List<SecurityAdvisory> advisories = this.securityAdvisoriesManager.getAdvisoriesWithStatus("announced", false);
        for (SecurityAdvisory advisory : advisories) {
            if (advisory.getEmbargoDate() != null
                && currentDate.toInstant().isAfter(advisory.getEmbargoDate().toInstant())) {
                this.securityAdvisoriesManager.saveDisablosable(advisory);
            }
        }
    }
}
