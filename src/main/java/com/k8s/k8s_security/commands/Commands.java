package com.k8s.k8s_security.commands;

import com.k8s.k8s_security.service.InspectorService;
import com.k8s.k8s_security.styles.Color;
import org.springframework.shell.CompletionContext;
import org.springframework.shell.CompletionProposal;
import org.springframework.shell.component.PathInput;
import org.springframework.shell.standard.*;

import java.nio.file.Path;
import java.util.List;

@ShellComponent
public class Commands extends AbstractShellComponent implements ValueProvider {
    private final InspectorService inspectorService;

    public Commands(InspectorService inspectorService) {
        this.inspectorService = inspectorService;
    }

    @ShellMethod(value = "Run trivy for scanning docker images", key = "trivy")
    public String trivy(@ShellOption(valueProvider = Commands.class) String arg) {
        return "You said " + Color.PURPLE.getColor() + " " + arg + " " + Color.RESET.getColor() + " ";
    }

    @ShellMethod(value = "Path input", key = "path")
    public void getPathForTrivy() {
        Path pathToProcess = getPathToProcess();
        System.out.println("Got value " + pathToProcess);
        inspectorService.runTrivyScan(pathToProcess);
    }

    @ShellMethod(value = "Path input", key = "path")
    public void getPathForProcessingCVEs() {
        Path pathToProcess = getPathToProcess();
        System.out.println("Got value ");
        inspectorService.runCveCounter(pathToProcess.toString());
    }

    @ShellMethod(value = "Path input", key = "path")
    public void getPathForProcessingCVEsInfo() {
        Path pathToProcess = getPathToProcess();
        inspectorService.runCveInfo(pathToProcess.toString());
        System.out.println("Got value ");
    }

    @Override
    public List<CompletionProposal> complete(CompletionContext completionContext) {
        return List.of();
    }

    private Path getPathToProcess() {
        PathInput component = new PathInput(getTerminal(), "Enter path to process folder");
        component.setResourceLoader(getResourceLoader());
        component.setTemplateExecutor(getTemplateExecutor());
        PathInput.PathInputContext context = component.run(PathInput.PathInputContext.empty());
        return context.getResultValue();
    }
}
