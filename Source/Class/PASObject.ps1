Class PASObject {

    
    PASObject () {
        if ($this.GetType() -eq [PASObject]) {
            throw "This class cannot be used to create an instance. Please inherit from this class only."
        }
    }





}
