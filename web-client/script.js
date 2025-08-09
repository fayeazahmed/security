const loginForm = document.getElementById("login-form");
const loginContainer = document.getElementById("login-container");
const authContainer = document.getElementById("auth-container");
const errorMessage = document.getElementById("error-message");
const logoutBtn = document.getElementById("logout-btn");
const authUsername = document.getElementById("auth-username");

const API_URL = "http://localhost:8080/api";
const JWT = "jwtToken";

loginForm.addEventListener("submit", login);

async function login(e) {
    e.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    try {
        const response = await fetch(API_URL + "/authenticate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || "Login failed");
        }

        const data = await response.json()
        console.log(data);
        localStorage.setItem(JWT, data.jwtToken);
        showAuthenticated(data.username);
    } catch (error) {
        errorMessage.textContent = error.message;
    }
}

logoutBtn.addEventListener("click", () => {
    localStorage.removeItem(JWT);
    showLogin();
});

function showAuthenticated(username) {
    loginContainer.classList.add("hidden");
    authContainer.classList.remove("hidden");
    authUsername.textContent = username;
}

function showLogin() {
    loginContainer.classList.remove("hidden");
    authContainer.classList.add("hidden");
    errorMessage.textContent = "";
}

async function fetchUser(token) {
    const response = await fetch(API_URL + "/authenticate", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        }
    });

    if (!response.ok) {
        localStorage.removeItem(JWT);
        showLogin();
    }

    return await response.json();
}

document.addEventListener("DOMContentLoaded", async () => {
    try {
        const response = await fetch("http://localhost:8080/api/oauth2", {
            method: "GET",
            credentials: "include",
        })
        const user = await response.json();
        console.log(user);
        showAuthenticated(user.login);
    } catch (e) {
        console.log(e);
    }

    const token = localStorage.getItem(JWT);
    if (token) {
        try {
            const user = await fetchUser(token);
            console.log(user);
            showAuthenticated(user.username);
        } catch (err) {
            console.error("Failed to load user:", err);
            localStorage.removeItem(JWT);
        }
    }
});