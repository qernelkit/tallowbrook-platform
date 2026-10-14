import SwiftUI

struct LoginView: View {
    @Environment(AppServices.self) private var services
    @State private var model: LoginViewModel?

    var body: some View {
        Group {
            if let model {
                LoginForm(model: model)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Sign in")
        .onAppear {
            if model == nil {
                model = LoginViewModel(api: services.api, breachCheck: PasswordBreachCheck(session: services.api.session))
            }
        }
    }
}

private struct LoginForm: View {
    @Bindable var model: LoginViewModel

    var body: some View {
        Form {
            Section {
                TextField("Email", text: $model.email)
                    .textContentType(.username)
                    .keyboardType(.emailAddress)
                    .textInputAutocapitalization(.never)
                SecureField("Password", text: $model.password)
                    .textContentType(model.isCreatingAccount ? .newPassword : .password)
                    .onChange(of: model.password) {
                        Task { await model.passwordChanged() }
                    }
                if let warning = model.breachWarning {
                    Label(warning, systemImage: "exclamationmark.shield")
                        .foregroundStyle(.orange)
                        .font(.footnote)
                }
            }

            Section {
                Toggle("I'm new to Tallowbrook", isOn: $model.isCreatingAccount)
            }

            Section {
                Button(model.isCreatingAccount ? "Create account" : "Sign in") {
                    Task { await model.submit() }
                }
                .disabled(!model.canSubmit)
            }

            if case .failed(let message) = model.state {
                Section {
                    Text(message).foregroundStyle(.red)
                }
            }
        }
    }
}
