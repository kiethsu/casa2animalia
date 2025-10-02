# Disaster Recovery Plan

## 1. Overview

The purpose of this Disaster Recovery Plan (DRP) is to minimize downtime and data loss in the event of an outage or disaster, and to ensure rapid restoration of services for the SmartVet system. This document outlines the procedures for backing up data, restoring systems, and responding to incidents.

Our environment is comprised of:
- **Database:** MongoDB Atlas (cloud-based database with automated backup capabilities).
- **Hosting/Domain:** Render (our deployed application runs on Render).
- **Backend Repository:** GitHub (source code versioned and maintained on GitHub).

## 2. Scope

This DRP covers:
- Backup and restoration of the MongoDB Atlas database.
- Recovery procedures for application files and configuration from GitHub.
- Restarting the application on Render.
- Logging and monitoring of system events.
- Automated cleanup of outdated records via cron jobs.
- Incident communication and escalation.

## 3. Backup Procedures

### 3.1 Database Backups
- **MongoDB Atlas Backups:**  
  MongoDB Atlas provides continuous cloud backups with automated snapshots. Ensure that:
  - Automated backups are enabled.
  - Backup retention policies are configured to retain snapshots for a period sufficient for recovery needs.
  - Regular verification of backup integrity is performed through periodic test restores.

### 3.2 Application Files and Code
- **GitHub Repository:**  
  The source code is maintained on GitHub. A complete history of code commits and releases is available, enabling rollbacks if needed.
  - Ensure that all production changes are committed and pushed.
  - Tag stable releases to mark production versions.

### 3.3 File Storage and Assets
- **Static Files and Media:**  
  Any uploaded files (e.g., pet images) are stored in the Render environment (or external cloud storage if configured). Regularly back up these files by:
  - Scheduling file system backups or syncing to an external storage solution.

## 4. Recovery Steps

### 4.1 Database Recovery
1. **Verify the Latest Snapshot:**  
   Log in to MongoDB Atlas and verify that recent backups exist and are intact.
2. **Initiate Restore Process:**  
   In case of data corruption or loss, use the MongoDB Atlas restore feature:
   - Select the desired snapshot.
   - Follow the prompts to restore the database to a new cluster or overwrite the existing one.
3. **Validate Data Integrity:**  
   Once restored, run a series of automated tests or scripts to ensure that all critical data is accurate and accessible.

### 4.2 Application Code Recovery
1. **Deploy from GitHub:**  
   If an outage is caused by corrupted code or server issues:
   - Pull the latest stable release from GitHub.
   - Use your CI/CD pipeline (or manual deployment process) to redeploy the application to Render.
2. **Reapply Configuration:**  
   Ensure that environment variables (e.g., for database connections, encryption keys) are correctly set on Render.
3. **Restart the Application:**  
   Trigger a restart from the Render dashboard or via the CLI, and confirm that the application is accessible.

### 4.3 File and Asset Recovery
1. **Restore Static Files:**  
   If static assets are lost, restore them from the latest backup or external storage.
2. **Verify File Integrity:**  
   Confirm that all media files are present and correctly linked within the application.

## 5. Incident Response

### 5.1 Immediate Actions
- **Log Analysis:**  
  Review **combined.log** and **error.log** files for a detailed record of events leading up to the incident.
- **Notify the IT Team:**  
  Follow the escalation procedures listed in this document. Contact the designated IT personnel and provide log file excerpts.
- **Assess Impact:**  
  Quickly determine which services or components are affected.

### 5.2 Communication
- **Internal Notification:**  
  Inform relevant team members (operations, support, management) via the established communication channels (email, messaging apps).
- **External Notification:**  
  If the incident impacts customers, send out a status update via the website, social media, or email, as appropriate.

### 5.3 Post-Incident Review
- **Incident Report:**  
  After resolution, create an incident report detailing the cause, impact, recovery actions taken, and lessons learned.
- **Plan Updates:**  
  Update the Disaster Recovery Plan if any gaps or improvements are identified.

## 6. Log Files

We maintain the following logs for troubleshooting and recovery:
- **combined.log:**  
  Captures general application events and informational messages.
- **error.log:**  
  Records errors and exceptions that occur during system operation.

These logs are essential for diagnosing issues and ensuring that all steps of the recovery process are validated.

## 7. Automated Cron Jobs

Our server leverages scheduled tasks (via [node-cron](https://www.npmjs.com/package/node-cron)) to maintain system health and reduce clutter. For example:
- A cron job runs every minute to clear out old canceled reservations and unassigned approved reservations.
- These jobs help ensure that the database remains optimized and that recovery processes run more efficiently by reducing the overall data load.

## 8. Additional Considerations

- **MongoDB Atlas:**  
  Our use of MongoDB Atlas means that we benefit from its built-in backup and restore capabilities, which are a key part of our recovery process.
- **Render Hosting:**  
  Since our domain is hosted on Render, our deployment procedures and recovery steps include actions specific to Render’s platform (e.g., using the Render dashboard to restart services).
- **GitHub as Source of Truth:**  
  Our backend code is fully managed on GitHub. In any recovery scenario, GitHub serves as the definitive source for our application code, and its version history is used to roll back to a known stable state if necessary.

## 9. Testing and Maintenance

- **Regular Testing:**  
  The DRP should be tested periodically through simulated drills. This ensures that every team member knows their role and that the recovery procedures work as expected.
- **Plan Review:**  
  Update this document regularly, especially after significant system changes (e.g., moving to a new hosting provider or updating the backup strategy).
- **Training:**  
  Ensure that all IT and operational team members are trained on the DRP and understand how to access and execute the procedures outlined here.

---

*By following this Disaster Recovery Plan, the SmartVet system ensures that even in the event of a catastrophic failure, our operations can be restored quickly, data integrity is maintained, and users experience minimal disruption.*

