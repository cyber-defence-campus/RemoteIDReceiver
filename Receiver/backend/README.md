## Coding rules

### Format of docstring

This project uses Google docstrings format. It can usually be defined in the IDEs. For **Pycharm** go to **File->
Settings->Tools->Python Integrated Tools** and set under **section Docstrings** the option for **Docstring format** to
Google.

For **VS Code** a Plugin is used which helps auto generate docstrings. The plugins name is [autoDocstring - Python
Docstring Generator](https://marketplace.visualstudio.com/items?itemName=njpwerner.autodocstring). Install it and then
go to **File->Preferences->Settings->Extensions->Python** and in **section Auto Docstring: Docstring Format** choose
Google.

### importing modules

the root is set to the directory `/dronesniffer`. To import a model from the `/models` directory the following import
statement will be made:
`models.some_model.py`.

## Run Tests

**_WARNING:_**
to successfully run the tests on the command line, one has to be in the 
subdirectory `/Receiver` (there are some relative paths, that otherwise 
will not work).

tests are written with unittest and pytest. the structure is based on the Arrange-Act-Assert pattern. To run all tests
simply type in the command `pytest` in the terminal and all found tests will be executed.

Tests will be found if the test files as well as the functions are prefixed with `test_`. To group tests, for example
multiple tests for one method, a class can be created as follows:

```angular2html
class TestSomeFunction:
    def test_when_case_then_result(self):
        # Arrange-Act-Assert

    def test_when_other_case_then_result(self):
        # Arrange-Act-Assert
```
