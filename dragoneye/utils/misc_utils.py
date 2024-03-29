import glob
import json
import os
from datetime import datetime
from functools import lru_cache
from shutil import rmtree
from typing import List

import backoff
import pyjq
import requests
import yaml

from dragoneye.utils.app_logger import logger


def elapsed_time(message=None):
    def _elapsed_time(function):
        def elapsed_wrapper(*arguments):
            start = datetime.now()
            return_val = function(*arguments)
            end = datetime.now()
            _message = message or 'The function ' + f'`{function.__name__}`' + 'took {} seconds'
            logger.info(_message.format((end - start).total_seconds()))
            return return_val
        return elapsed_wrapper
    return _elapsed_time


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

    make_directory(base_path)
    make_directory(f"{base_path}/account-data")
    make_directory(account_data_dir)
    return os.path.abspath(account_data_dir)


def load_yaml(file_path: str) -> List[dict]:
    with open(file_path, "r") as file:
        return yaml.safe_load(file)


def _on_backoff_success(details: dict) -> None:
    logger.info('Invoked request took {elapsed:0.6f} seconds for call {args[0]}'.format(**details))


def _on_backoff_predicate(details: dict) -> None:
    logger.info('Attempt #{tries} failed. Invoked request took {elapsed:0.6f} seconds for call {args[0]}'.format(**details))


def _on_backoff_giveup(details: dict) -> None:
    logger.info('Given up on request for {args[0]}'.format(**details))


@backoff.on_exception(backoff.expo, requests.RequestException, 10, 600)
@backoff.on_predicate(backoff.expo, lambda response: response.status_code != 200, 3, 600,
                      on_success=_on_backoff_success,
                      on_backoff=_on_backoff_predicate,
                      on_giveup=_on_backoff_giveup)
def invoke_get_request(url: str, headers: dict):
    return requests.get(url=url, headers=headers)


@lru_cache(maxsize=None)
def get_dynamic_values_from_files(value: str, directory: str) -> list:
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
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode()
    raise TypeError("Unknown type")


def snakecase(string):
    return string.replace("-", "_")
