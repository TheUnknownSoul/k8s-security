package com.k8s.k8s_security.service;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.styles.Color;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;

@Service
public class InspectorService {

    @Value("classpath:scripts/CVE_counter.py")
    private Resource cveCounter;
    @Value("classpath:scripts/cve_info.py")
    private Resource cveInfo;

    public void runTrivyScan(Path path) {
        if (path != null) {
            Runtime runtime = Runtime.getRuntime();
            try {

                runtime.exec(String.format("/usr/bin/trivy %s", path));
            } catch (IOException e) {
                throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
            }
        }
    }

    public void runCveCounter(String path) {
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(String.format("python %s %s", cveCounter.getFile().getAbsoluteFile(), path));

        } catch (IOException e) {
            throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
        }
    }

    public void runCveInfo(String path) {
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(String.format("python " + cveInfo.getFile().getAbsoluteFile() + " %s", path));
        } catch (IOException e) {
            throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
        }

    }
}
