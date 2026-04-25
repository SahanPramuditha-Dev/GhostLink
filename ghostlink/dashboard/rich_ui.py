from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def build_layout(state) -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
    )

    header = Table.grid(expand=True)
    header.add_column(justify="center")
    header.add_row(
        f"[bold cyan]Target:[/] {state.target_ssid}   "
        f"[bold cyan]Status:[/] {state.status}   "
        f"[bold cyan]Attempts:[/] {state.attempts}"
    )
    layout["header"].update(Panel(header, style="cyan"))

    body = Table.grid(expand=True)
    body.add_column()
    body.add_row(f"Trying: [yellow]{state.current_password}")
    body.add_row(f"Speed: {state.speed:.1f} passwords/sec")
    if state.total_combinations:
        pct = (state.attempts / state.total_combinations) * 100
        body.add_row(
            f"Progress: [green]{'#' * int(pct // 5)}{'-' * (20 - int(pct // 5))}[/] {pct:.1f}%"
        )
    layout["body"].update(Panel(body, title="Stats", border_style="green"))
    return layout
