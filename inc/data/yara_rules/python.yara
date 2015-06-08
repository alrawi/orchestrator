rule python_script: python script text source
{
    strings:
        $import = /import [a-zA-Z0-9]+/

    condition:
        $import
}
