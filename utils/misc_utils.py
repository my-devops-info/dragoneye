import glob
import inspect
import json
import os
from datetime import datetime
from shutil import rmtree
from typing import List

import backoff
import pyjq
import requests
import yaml


def elapsed_time(function):
    def elapsed_wrapper(*arguments):
        start = datetime.now()
        return_val = function(*arguments)
        end = datetime.now()
        print(f'The function `{function.__name__}` took {(end - start).total_seconds()} seconds')
        return return_val
    return elapsed_wrapper


def make_directory(path) -> None:
    try:
        os.mkdir(path)
    except OSError:
        # Already exists
        pass


def init_directory(base_path: str, account_name: str, clean: bool) -> str:
    account_data_dir = f"{base_path}/account-data/{account_name}"
    if clean and os.path.exists(account_data_dir):
        rmtree(account_data_dir)

    make_directory(f"{base_path}/account-data")
    make_directory(account_data_dir)
    return os.path.abspath(account_data_dir)


def get_commands() -> List[dict]:
    dir_path = os.path.dirname(inspect.stack()[1].filename)
    collect_commands_path = os.path.join(dir_path, "collect_commands.yaml")
    with open(collect_commands_path, "r") as file:
        return yaml.safe_load(file)


def _on_backoff_success(details: dict) -> None:
    print('Invoked request took {elapsed:0.6f} seconds for call {args[0]}'.format(**details))


def _on_backoff_predicate(details: dict) -> None:
    print('Attempt #{tries} failed. Invoked request took {elapsed:0.6f} seconds for call {args[0]}'.format(**details))


def _on_backoff_giveup(details: dict) -> None:
    print('Given up on request for {args[0]}'.format(**details))


@backoff.on_exception(backoff.expo, requests.RequestException, 10, 600)
@backoff.on_predicate(backoff.expo, lambda response: response.status_code != 200, 3, 600,
                      on_success=_on_backoff_success,
                      on_backoff=_on_backoff_predicate,
                      on_giveup=_on_backoff_giveup)
def invoke_get_request(url: str, headers: dict):
    return requests.get(url=url, headers=headers)


def get_dynamic_values_from_files(value: str, directory: str):
    parameter_file = value.split("|")[0]
    parameter_file = "{}/{}".format(
        directory, parameter_file
    )

    # Get array if a globbing pattern is used (ex. "*.json")
    parameter_files = glob.glob(parameter_file)
    parameters = []
    for parameter_file in parameter_files:
        if not os.path.isfile(parameter_file):
            continue

        with open(parameter_file, "r") as file:
            parameter_values = json.load(file)
            pyjq_parse_string = "|".join(value.split("|")[1:])
            for parameter in pyjq.all(pyjq_parse_string, parameter_values):
                if isinstance(parameter, list):
                    parameters.extend(parameter)
                else:
                    parameters.append(parameter)
    return parameters


def custom_serializer(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode()
    raise TypeError("Unknown type")


def snakecase(string):
    return string.replace("-", "_")
