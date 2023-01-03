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
package org.xwiki.contrib.securityadvisory;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.xwiki.model.reference.DocumentReference;
import org.xwiki.user.UserReference;

/**
 * Represents a security advisory.
 *
 * @version $Id$
 * @since 1.0
 */
public class SecurityAdvisory
{
    /**
     * Possible states of the advisory.
     *
     * @version $Id$
     * @since 1.0
     */
    public enum State
    {
        /**
         * When the advisory is still in writing process.
         */
        DRAFT,

        /**
         * When the advisory has been completed but is not announced internally or externally.
         */
        COMPLETED,

        /**
         * When the advisory has been announced internally, but not disclosed.
         */
        ANNOUNCED,

        /**
         * When the advisory has been announced and the embargo time is finished.
         */
        DISCLOSABLE,

        /**
         * When the advisory has been publicly disclosed and a CVE has been created for it.
         */
        DISCLOSED,

        /**
         * When the advisory has been discarded for some reasons but the data need to be kept.
         */
        DISCARDED
    };

    private final DocumentReference holderReference;
    private List<String> affectedVersions;
    private List<String> patchedVersions;
    private List<String> impactedModules;
    private Date embargoDate;
    private boolean computeEmbargoDate;
    private State state;
    private String cveId;
    private UserReference author;
    private List<String> tickets;
    private String title;
    private String content;
    private String product;
    private String severity;
    private String advisoryLink;

    /**
     * Default constructor.
     * @param documentReference the reference of the document containing the advisory data
     */
    public SecurityAdvisory(DocumentReference documentReference)
    {
        this.holderReference = documentReference;
    }

    /**
     * @return the reference of the document containing the advisory data
     */
    public DocumentReference getHolderReference()
    {
        return holderReference;
    }

    /**
     * The affected versions can be represented as independent versions or as interval of versions.
     *
     * @return the list of affected versions
     */
    public List<String> getAffectedVersions()
    {
        return affectedVersions;
    }

    /**
     * The affected versions can be represented as independent versions or as interval of versions.
     *
     * @param affectedVersions the list of affected versions
     * @return the current instance
     */
    public SecurityAdvisory setAffectedVersions(List<String> affectedVersions)
    {
        this.affectedVersions = affectedVersions;
        return this;
    }

    /**
     * The patched versions should always be represented as independent versions.
     *
     * @return the list of patched versions
     */
    public List<String> getPatchedVersions()
    {
        return patchedVersions;
    }

    /**
     * The patched versions should always be represented as independent versions.
     *
     * @param patchedVersions the list of patched versions
     * @return the current instance
     */
    public SecurityAdvisory setPatchedVersions(List<String> patchedVersions)
    {
        this.patchedVersions = patchedVersions;
        return this;
    }

    /**
     * @return the embargo date or {@code null} if not yet computed
     */
    public Date getEmbargoDate()
    {
        return embargoDate;
    }

    /**
     * @param embargoDate the date of the embargo for this advisory
     * @return the current instance
     */
    public SecurityAdvisory setEmbargoDate(Date embargoDate)
    {
        this.embargoDate = embargoDate;
        return this;
    }

    /**
     * @return {@code true} if the {@link #getEmbargoDate()} should be automatically computed, {@code false} otherwise
     */
    public boolean isComputeEmbargoDate()
    {
        return computeEmbargoDate;
    }

    /**
     * @param computeEmbargoDate {@code true} if the {@link #getEmbargoDate()} should be automatically computed,
     *                           {@code false} otherwise
     * @return the current instance
     */
    public SecurityAdvisory setComputeEmbargoDate(boolean computeEmbargoDate)
    {
        this.computeEmbargoDate = computeEmbargoDate;
        return this;
    }

    /**
     * @return the state of the advisory
     */
    public State getState()
    {
        return state;
    }

    /**
     * @param state the state of the advisory
     * @return the current instance
     */
    public SecurityAdvisory setState(State state)
    {
        this.state = state;
        return this;
    }

    /**
     * @return the actual CVE ID if a CVE has been issued
     */
    public String getCveId()
    {
        return cveId;
    }

    /**
     * @param cveId the CVE identifier
     * @return the current instance
     */
    public SecurityAdvisory setCveId(String cveId)
    {
        this.cveId = cveId;
        return this;
    }

    /**
     * @return the author of the advisory
     */
    public UserReference getAuthor()
    {
        return author;
    }

    /**
     * @param author the author of the advisory
     * @return the current instance
     */
    public SecurityAdvisory setAuthor(UserReference author)
    {
        this.author = author;
        return this;
    }

    /**
     * @return the list of related issue tracker tickets
     */
    public List<String> getTickets()
    {
        return tickets;
    }

    /**
     * @param tickets the list of related issue tracker tickets
     * @return the current instance
     */
    public SecurityAdvisory setTickets(List<String> tickets)
    {
        this.tickets = tickets;
        return this;
    }

    /**
     * @return the title of the advisory
     */
    public String getTitle()
    {
        return title;
    }

    /**
     * @param title the title of the advisory
     * @return the current instance
     */
    public SecurityAdvisory setTitle(String title)
    {
        this.title = title;
        return this;
    }

    /**
     * @return the content of the advisory
     */
    public String getContent()
    {
        return content;
    }

    /**
     * @param content the content of the advisory
     * @return the current instance
     */
    public SecurityAdvisory setContent(String content)
    {
        this.content = content;
        return this;
    }

    /**
     * @return the list of maven modules impacted
     */
    public List<String> getImpactedModules()
    {
        return impactedModules;
    }

    /**
     * @param impactedModules the list of maven modules impacted
     * @return the current instance
     */
    public SecurityAdvisory setImpactedModules(List<String> impactedModules)
    {
        this.impactedModules = impactedModules;
        return this;
    }

    /**
     * @return the name of the product this advisory targets
     */
    public String getProduct()
    {
        return product;
    }

    /**
     * Define the product this advisory targets.
     *
     * @param product the name of the product this advisory targets
     * @return the current instance
     */
    public SecurityAdvisory setProduct(String product)
    {
        this.product = product;
        return this;
    }

    /**
     * @return the severity of the advisory
     */
    public String getSeverity()
    {
        return severity;
    }

    /**
     * @param severity the severity of the advisory
     * @return the current instance
     */
    public SecurityAdvisory setSeverity(String severity)
    {
        this.severity = severity;
        return this;
    }

    /**
     * @return a link to the advisory
     */
    public String getAdvisoryLink()
    {
        return advisoryLink;
    }

    /**
     * @param advisoryLink a link to the advisory
     * @return the current instance
     */
    public SecurityAdvisory setAdvisoryLink(String advisoryLink)
    {
        this.advisoryLink = advisoryLink;
        return this;
    }

    /**
     * Compute if the advisory should be made disclosable. This should happen when the advisory is
     * {@link State#ANNOUNCED} and the embargo date is over.
     *
     * @return {@code true} if the advisory can be disclosed.
     */
    public boolean isDisclosable()
    {
        return getState() == State.ANNOUNCED
            && getEmbargoDate() != null
            && Instant.now().isAfter(getEmbargoDate().toInstant());
    }
}
