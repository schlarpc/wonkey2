import argparse

from .template import create_template


def get_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-minify", action="store_true", default=False)
    parser.add_argument(
        "--no-allow-debug-logging",
        action="store_false",
        dest="allow_debug_logging",
        default=True,
        help="""
            Suppresses the ability to enable Lambda@Edge logging.
            The StackSet of CloudWatch log groups is not added to the template, allowing
            the template generated with this flag set to be uploaded to the Serverless App Repo.
        """,
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = get_args(argv)
    template = create_template(allow_debug_logging=args.allow_debug_logging)
    json_kwargs = {"sort_keys": True}
    if not args.no_minify:
        json_kwargs.update({"indent": None, "separators": (",", ":")})
    print(template.to_json(**json_kwargs))
