# Steam Login Helper

![Kotlin](https://img.shields.io/badge/kotlin-2.2.20-blue.svg?logo=kotlin)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-gray?&logo=GitHub-Sponsors&logoColor=EA4AAA)](https://github.com/sponsors/StefanOltmann)

**Amazon AWS Lambda function for Steam login**

Enables users to authenticate via Steam and generates a JWT token as proof of Steam ID ownership.

## Packaging the application

The application can be packaged using:

```shell script
./gradlew buildLambdaRelease
```

This will create a file named `steam-login-helper.zip` in `build/lambda/release/`.

## Deploying the function

1. Go to the [Lambda Console](https://console.aws.amazon.com/lambda/home).
2. Click on "Create function".
3. Leave "Author from scratch" selected.
4. Enter the function name: "SteamLoginHelper".
5. Choose "Amazon Linux 2 runtime".
6. Choose arm64 runtime.
7. Enable "Function URL" (under "Additional configurations").
8. Set the "Auth type" to "NONE".
9. Click on "create function".
10. Click to the `Code` tab.
11. Upload the `steam-login-helper.zip` in the `Code source` panel.
12. Click `Edit` on the `Runtime settings` panel.
13. Set the `Handler` in the `Runtime settings` to `steam-login-helper.kexe`.
14. Click on `Save`.
15. You can now call the displayed "Function URL" and you should see a valid response.
16. Click on the `Configuration` and select `Environment variables` on the left side.
17. Add key `ISSUER` and set it to your service name.
18. Add key `SALT` and set it to a random string like `my53cr375A17`.
19. Add key `JWT_PRIVATE_KEY` and set it to your DER base64-encoded JWT private key (`MII...`).
20. Click on `Save`.

The function should now be ready.

Call the function URL with `/login?redirect=https://myservice.com`.

This will eventually call `https://myservice.com?token=eyXYZ`.

## Known issues

SSL verification is turned off right now.
The call to the Steam server errored.

## Acknowledgements

* JetBrains for making [Kotlin](https://kotlinlang.org).
* Viacheslav Ivanovichev for making [Kotlin Native Runtime for AWS Lambda](https://github.com/trueangle/kotlin-native-aws-lambda-runtime).
* Oleg Yukhnevich for making [cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin).
* Andreas Schulz for making [JWT Kotlin Multiplatform](https://github.com/Appstractive/jwt-kt).

## Contributions

Contributions to this project are welcome! If you encounter any issues,
have suggestions for improvements, or would like to contribute new features,
please feel free to submit a pull request.

## License

Steam Login Helper is licensed under the GNU Affero General Public License (AGPL),
ensuring the community's freedom to use, modify, and distribute the software.

