Function Close-Session {
    Initialize-Function
    Invoke-Logoff -url $PVWAURL -logonHeader $Token -ErrorAction SilentlyContinue
}