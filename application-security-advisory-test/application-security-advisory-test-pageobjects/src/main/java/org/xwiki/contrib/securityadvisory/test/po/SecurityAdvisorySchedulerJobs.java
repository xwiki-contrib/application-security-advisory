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
package org.xwiki.contrib.securityadvisory.test.po;

import org.xwiki.scheduler.test.po.SchedulerHomePage;
import org.xwiki.test.ui.po.BaseElement;

/**
 * The scheduler jobs of the Security Advisory Application, as listed on the home page of the Scheduler application.
 *
 * @version $Id$
 * @since 2.3
 */
public class SecurityAdvisorySchedulerJobs extends BaseElement
{
    private static final String DISCLOSABLE_COMPUTATION_JOB = "Computation of security advisory disclosable advisories";

    /**
     * Trigger the job marking as disclosable the announced advisories whose embargo date is reached. The job runs in
     * the background: the advisories are updated after this method returns.
     */
    public void triggerDisclosableComputation()
    {
        SchedulerHomePage schedulerHomePage = SchedulerHomePage.gotoPage();
        getDriver().addPageNotYetReloadedMarker();
        schedulerHomePage.clickJobActionTrigger(DISCLOSABLE_COMPUTATION_JOB);
        getDriver().waitUntilPageIsReloaded();
    }
}
