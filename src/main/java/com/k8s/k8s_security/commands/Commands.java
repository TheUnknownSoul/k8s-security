package com.k8s.k8s_security.commands;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.providers.PathValueProvider;
import com.k8s.k8s_security.service.InspectorService;
import com.k8s.k8s_security.styles.Color;
import org.springframework.shell.component.ConfirmationInput;
import org.springframework.shell.component.context.ComponentContext;
import org.springframework.shell.component.flow.ComponentFlow;
import org.springframework.shell.component.support.SelectorItem;
import org.springframework.shell.standard.AbstractShellComponent;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.util.LinkedHashMap;
import java.util.Optional;

@ShellComponent
public class Commands extends AbstractShellComponent {
    private final InspectorService inspectorService;
    private final ComponentFlow.Builder componentFlowBuilder;
    private static String workingDirectory;

    public Commands(InspectorService inspectorService, ComponentFlow.Builder componentFlowBuilder) {
        this.inspectorService = inspectorService;
        this.componentFlowBuilder = componentFlowBuilder;
    }

    @ShellMethod(key = "trivy", value = "Run trivy for scanning docker images")
    public void getPathForTrivy() {
        System.out.printf("%s [+]Scanning images in directory: %s %s %n", Color.BlUE.getColor(), workingDirectory, Color.RESET.getColor());
        inspectorService.runTrivyScan(workingDirectory);
    }

    @ShellMethod(key = "Check RBAC", value = "Check role-based access control")
    public void RBAC_Check() {
        System.out.printf("%s [+]Checking roles and bindings: %s %s %n", Color.BlUE.getColor(), workingDirectory, Color.RESET.getColor());
        inspectorService.runTrivyScan(workingDirectory);
    }

    @ShellMethod(key = "process CVE", value = "Count number of the same CVE`s")
    public void getPathForProcessingCVEs() {
        System.out.println(Color.BlUE.getColor() + "[+]Counting duplicates... " + Color.RESET.getColor());
        inspectorService.runCveCounter(workingDirectory);
    }

    @ShellMethod(key = "CVE info", value = "Get information about severity, CVSS and description")
    public void getPathForProcessingCVEsInfo() {
        System.out.println(Color.BlUE.getColor() + "[+]Gathering information about CVE`s... " + Color.RESET.getColor());
        inspectorService.runCveInfo(workingDirectory);
    }

    @ShellMethod(key = "run inspector flow", value = "Run all commands one by one")
    public void runInspectorFlow() {
        var items = new LinkedHashMap<String, String>();
        items.put("Run Trivy", "Run Trivy");
        items.put("Run RBAC", "Run RBAC");
        items.put("Count CVE's", "Count CVE's");
        items.put("Get CVE's info", "Get CVE's info");

        ComponentContext<?> ctx = componentFlowBuilder.clone().reset()
                .withSingleItemSelector("action")
                .name("Chosen Action")
                .selectItems(items)
                .next(c -> {
                    String sel = null;
                    Optional<SelectorItem<String>> optionalResultItem = c.getResultItem();
                    if (optionalResultItem.isPresent()) {
                        sel = optionalResultItem.get().getItem();
                    }
                    return sel;
                })
                .and()
                .build()
                .run().getContext();

        String action = ctx.get("action");
        switch (action) {
            case "Run Trivy":
                inspectorService.runTrivyScan(workingDirectory);
                break;
            case "Run RBAC":
                inspectorService.runRbacCheck();
                break;
            case "Count CVE's":
                inspectorService.runCveCounter(workingDirectory);
                break;
            case "Get CVE's info":
                inspectorService.runCveInfo(workingDirectory);
                break;
        }
    }


    @ShellMethod(value = "set working directory with images", key = "set path")
    public void getPathToProcess(@ShellOption(help = "Enter path", valueProvider = PathValueProvider.class) String path) {
        boolean isReadyToProcess = checkConfirmation();
        if (isReadyToProcess) {
            System.out.println("[✅]Working directory is set to: " + Color.GREEN.getColor() + path + Color.RESET.getColor());
            if (path != null && !path.trim().isEmpty()) {
                workingDirectory = path;
            } else {
                throw new SomethingWentWrongException("[x]Path couldn't be empty");
            }
        }
    }

    private boolean checkConfirmation() {
        ConfirmationInput component = new ConfirmationInput(getTerminal(), "Are you sure?", false);
        component.setResourceLoader(getResourceLoader());
        component.setTemplateExecutor(getTemplateExecutor());
        ConfirmationInput.ConfirmationInputContext context = component.run(ConfirmationInput.ConfirmationInputContext.empty());
        return context.getResultValue();
    }

}
