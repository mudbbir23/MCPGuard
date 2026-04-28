import ora from "ora";
import chalk from "chalk";
import Table from "cli-table3";

export async function registryCommand(query: string | undefined, options: { apiUrl: string }) {
  const spinner = ora("Fetching MCP registry...").start();

  try {
    const searchParam = query ? `?search=${encodeURIComponent(query)}` : "";
    const res = await fetch(`${options.apiUrl}/registry${searchParam}`);
    
    if (!res.ok) {
      throw new Error("Failed to fetch registry");
    }

    const data = await res.json();
    spinner.stop();

    if (data.servers.length === 0) {
      console.log(chalk.yellow(`No servers found${query ? ` matching "${query}"` : ""}.`));
      return;
    }

    console.log(`\nFound ${chalk.bold(data.total)} server(s):\n`);

    const table = new Table({
      head: [
        chalk.gray("Server Name"),
        chalk.gray("Category"),
        chalk.gray("Score"),
        chalk.gray("GitHub URL")
      ],
      style: { head: [], border: [] }
    });

    data.servers.forEach((s: any) => {
      const scoreColor = 
        s.latest_score === "CRITICAL" ? chalk.bgRed.white.bold :
        s.latest_score === "HIGH" ? chalk.bgKeyword("orange").white.bold :
        s.latest_score === "MEDIUM" ? chalk.bgYellow.black.bold :
        s.latest_score === "LOW" ? chalk.bgBlue.white.bold :
        s.latest_score === "SAFE" ? chalk.bgGreen.white.bold :
        chalk.bgGray.white.bold;

      table.push([
        chalk.white.bold(s.name),
        s.category,
        scoreColor(` ${s.latest_score || "UNSCANNED"} `),
        chalk.dim(s.github_url)
      ]);
    });

    console.log(table.toString());
    console.log(`\nView full registry at: ${chalk.blue("http://localhost:3000/registry")}\n`);

  } catch (err: any) {
    spinner.fail(chalk.red("Failed to fetch registry"));
    console.error(chalk.red(`Error: ${err.message}`));
    process.exit(1);
  }
}
