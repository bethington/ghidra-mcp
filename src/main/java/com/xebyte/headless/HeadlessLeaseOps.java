package com.xebyte.headless;

import com.xebyte.core.ProjectPaths;
import com.xebyte.core.ProjectVersionControl;
import com.xebyte.core.Refusal;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;

/** {@link CheckoutLeases.Ops} over the headless provider's open project. */
final class HeadlessLeaseOps implements CheckoutLeases.Ops {

    private final HeadlessProgramProvider provider;
    private final ProjectVersionControl versionControl;

    HeadlessLeaseOps(HeadlessProgramProvider provider, ProjectVersionControl versionControl) {
        this.provider = provider;
        this.versionControl = versionControl;
    }

    private DomainFile file(String path) {
        Project project = provider.getProject();
        if (project == null) {
            return null;
        }
        try {
            return ProjectPaths.file(project, path);
        } catch (Refusal gone) {
            return null;
        }
    }

    @Override
    public long modificationStamp(String path) {
        for (Program program : provider.getAllOpenPrograms()) {
            DomainFile file = program.getDomainFile();
            if (file != null && path.equals(file.getPathname())) {
                return program.getModificationNumber();
            }
        }
        return CheckoutLeases.NOT_OPEN;
    }

    @Override
    public boolean isCheckedOut(String path) {
        DomainFile file = file(path);
        return file != null && file.isCheckedOut();
    }

    @Override
    public boolean modifiedOnDisk(String path) {
        DomainFile file = file(path);
        return file != null && file.modifiedSinceCheckout();
    }

    @Override
    public boolean checkin(String path, String comment) {
        versionControl.checkin(path, comment, false, false);
        return !isCheckedOut(path);
    }

    @Override
    public boolean release(String path) {
        provider.releaseCachedProgram(path, false);
        versionControl.undoCheckout(path, false);
        return !isCheckedOut(path);
    }

    @Override
    public void closeCopy(String path) {
        provider.releaseCachedProgram(path, false);
    }
}
