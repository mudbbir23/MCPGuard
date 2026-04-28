import ora from "ora";
import chalk from "chalk";

function detectTargetType(target: string): "github" | "npm" | "local" {
  if (/^https?:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+\/?$/.test(target)) {
    return "github";
  }
  return "npm";
}

export async function scanCommand(target: string, options: { wait: boolean; apiUrl: string }) {
  const type = detectTargetType(target);
  const spinner = ora(`Initializing scan for ${chalk.cyan(target)}...`).start();

  try {
    // 1. Start scan
    const startRes = await fetch(`${options.apiUrl}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target, target_type: type }),
    });

    if (!startRes.ok) {
      const err = await startRes.json();
      throw new Error(err?.error?.message || "Failed to start scan");
    }

    const { scan_id } = await startRes.json();
    spinner.succeed(`Scan started! ID: ${chalk.dim(scan_id)}`);

    if (!options.wait) {
      console.log(`\nView results at: ${chalk.blue(`http://localhost:3000/scan/${scan_id}`)}`);
      return;
    }

    // 2. Poll for results
    spinner.start("Scanning in progress...");
    let result: any = null;
    let lastProgress = "";

    while (true) {
      const pollRes = await fetch(`${options.apiUrl}/scans/${scan_id}`);
      if (!pollRes.ok) throw new Error("Failed to poll scan status");
      
      const scanData = await pollRes.json();

      if (scanData.status === "complete") {
        result = scanData.result_json;
        break;
      } else if (scanData.status === "failed") {
        throw new Error(scanData.error_message || "Scan failed internally");
      }

      if (scanData.progress && scanData.progress !== lastProgress) {
        lastProgress = scanData.progress;
        spinner.text = scanData.progress;
      }

      // Wait 2 seconds before polling again
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }

    spinner.succeed("Scan completed!\n");

    // 3. Print Report
    const scoreColor = 
      result.overall_score === "CRITICAL" ? chalk.red.bold :
      result.overall_score === "HIGH" ? chalk.keyword("orange").bold :
      result.overall_score === "MEDIUM" ? chalk.yellow.bold :
      result.overall_score === "LOW" ? chalk.blue.bold :
      chalk.green.bold;

    console.log(`Overall Security Score: ${scoreColor(result.overall_score || "SAFE")}`);
    console.log(`Scan Duration: ${chalk.dim((result.scan_duration_ms / 1000).toFixed(1) + "s")}`);
    
    const { critical, high, medium, low, info } = result.severity_counts;
    console.log(`Findings: ${chalk.red(critical)} Critical | ${chalk.keyword("orange")(high)} High | ${chalk.yellow(medium)} Medium | ${chalk.blue(low)} Low | ${chalk.gray(info)} Info\n`);

    const allFindings = Object.values(result.categories || {}).flatMap(
      (cat: any) => cat.findings || []
    ) as any[];

    if (allFindings.length === 0) {
      console.log(chalk.green("✨ No security issues found!"));
    } else {
      allFindings.forEach((finding) => {
        const fColor = 
          finding.severity === "CRITICAL" ? chalk.red :
          finding.severity === "HIGH" ? chalk.keyword("orange") :
          finding.severity === "MEDIUM" ? chalk.yellow :
          finding.severity === "LOW" ? chalk.blue :
          chalk.gray;

        console.log(`${fColor(`[${finding.severity}]`)} ${chalk.bold(finding.title)}`);
        console.log(`    ${chalk.dim(finding.description)}`);
        if (finding.file_path) {
          console.log(`    ${chalk.dim("Location:")} ${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ""}`);
        }
        if (finding.remediation) {
          console.log(`    ${chalk.green("💡 " + finding.remediation)}`);
        }
        console.log("");
      });
    }

    console.log(`\nView detailed report at: ${chalk.blue(`http://localhost:3000/scan/${scan_id}`)}`);

    // Exit with code 1 if there are critical/high findings
    if (critical > 0 || high > 0) {
      process.exit(1);
    }

  } catch (err: any) {
    spinner.fail(chalk.red("Scan failed"));
    console.error(chalk.red(`Error: ${err.message}`));
    process.exit(1);
  }
}
