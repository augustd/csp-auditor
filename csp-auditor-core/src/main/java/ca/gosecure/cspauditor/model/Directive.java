package ca.gosecure.cspauditor.model;

import java.util.ArrayList;
import java.util.List;

public class Directive {
    private final String name;
    private final List<String> values;
    private final boolean implicit;

    public Directive(String name,List<String> values) {
        this.name = name;
        this.values = new ArrayList<>(values);
        this.implicit = false;
    }

    public Directive(String name,List<String> values,boolean implicit) {
        this.name = name;
        this.values = new ArrayList<>(values);
        this.implicit = implicit;
    }

    //Getters

    public String getName() {
        return name;
    }

    public List<String> getValues() {
        return values;
    }

    public boolean isImplicit() {
        return implicit;
    }

    ////Clones

    protected Directive clone(String name) {
        return new Directive(name, cloneArrayList(values), false);
    }
    protected Directive cloneImplicit(String name) {
        return new Directive(name, cloneArrayList(values), true);
    }

    private List<String> cloneArrayList(List<String> values) {
        List<String> newList = new ArrayList<String>();
        newList.addAll(values);
        return newList;
    }

    @Override
    public String toString() {
        return getName()+": "+ String.join(" ",getValues());
    }
}
