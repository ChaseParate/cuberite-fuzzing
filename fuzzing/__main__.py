import click

from fuzzing.fuzzer import fuzz


@click.group()
def cli():
    pass


cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
