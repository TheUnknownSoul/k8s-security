package com.k8s.k8s_security.commands;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.service.InspectorService;
import com.k8s.k8s_security.styles.Color;
import org.springframework.shell.CompletionContext;
import org.springframework.shell.CompletionProposal;
import org.springframework.shell.standard.AbstractShellComponent;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ValueProvider;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

@ShellComponent
public class Commands extends AbstractShellComponent implements ValueProvider {
    private final InspectorService inspectorService;

    public Commands(InspectorService inspectorService) {
        this.inspectorService = inspectorService;
    }

    @ShellMethod(value = "Run trivy for scanning docker images", key = "trivy")
    public void getPathForTrivy() {
        Console console = System.console();
        char[] sudoChars = console.readPassword("Enter password: ");
        if (sudoChars == null) {
            throw new SomethingWentWrongException("No password entered");
        }

//        Arrays.fill(sudoChars, ' ');
        String sudoPassword = Arrays.toString(sudoChars);
        String replace = sudoPassword.replace(',', ' ').replace('[', ' ').replace(']', ' ').replaceAll("\\s","").stripTrailing();
        Path pathToProcess = getPathToProcess();
        System.out.println(Color.BlUE.getColor() + "Got value "  +pathToProcess + " and " + sudoPassword + Color.RESET.getColor());
        inspectorService.runTrivyScan(pathToProcess, replace);
    }

    @ShellMethod(value = "Path input", key = "process CVE")
    public void getPathForProcessingCVEs() {
        Path pathToProcess = getPathToProcess();
        System.out.println(Color.BlUE.getColor() + "Path is set to: " + pathToProcess + Color.RESET.getColor());
        inspectorService.runCveCounter(pathToProcess.toString());
    }

    @ShellMethod(value = "Path input", key = "get CVE info")
    public void getPathForProcessingCVEsInfo() {
        Path pathToProcess = getPathToProcess();
        System.out.println(Color.BlUE.getColor() + "Path is set to: " + pathToProcess + Color.RESET.getColor());
        inspectorService.runCveInfo(pathToProcess.toString());

    }

    @Override
    public List<CompletionProposal> complete(CompletionContext completionContext) {
        return List.of();
    }

    private Path getPathToProcess() {
        String path;
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println(Color.PURPLE.getColor() + "Enter path to process: " + Color.RESET.getColor());
            path = bufferedReader.readLine();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (!path.isEmpty()) {

            return Path.of(path);
        }
        throw new SomethingWentWrongException("Path could not be null");

    }
}
