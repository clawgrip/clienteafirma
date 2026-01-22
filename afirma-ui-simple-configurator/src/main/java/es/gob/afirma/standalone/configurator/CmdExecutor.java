package es.gob.afirma.standalone.configurator;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import es.gob.afirma.standalone.configurator.common.ConfiguratorUtil;

public class CmdExecutor {

	public static Path copyCmdFromResources(String resourcePath) throws IOException {
		InputStream inputStream = CmdExecutor.class
				.getClassLoader()
				.getResourceAsStream(resourcePath);

		if (inputStream == null) {
			throw new FileNotFoundException("No se encontro el recurso: " + resourcePath); //$NON-NLS-1$
		}

		Path tempFile = Files.createTempFile("script-", ".cmd"); //$NON-NLS-1$ //$NON-NLS-2$
		Files.copy(inputStream, tempFile, StandardCopyOption.REPLACE_EXISTING);

		return tempFile;
	}

	public static void executePathCmd(Path cmdPath, Path path)
			throws IOException, InterruptedException {

		File workingDir = ConfiguratorUtil.getApplicationDirectory();

		ProcessBuilder pb = new ProcessBuilder(
				"cmd.exe", //$NON-NLS-1$
				"/c", //$NON-NLS-1$
				cmdPath.toAbsolutePath().toString(),
				path.toAbsolutePath().toString()
				);

		pb.directory(workingDir);
		pb.redirectErrorStream(true);

		Process p = pb.start();

		int exitCode = p.waitFor();
		if (exitCode != 0) {
			throw new IOException("El CMD termino con error. ExitCode=" + exitCode); //$NON-NLS-1$
		}
	}



}
