rm -rf build
mkdir build
cp -R src/* build
cp -R "$(dirname "$(pipenv run which python)")"/../lib/python3.8/site-packages/* build
terraform init terraform
terraform apply terraform