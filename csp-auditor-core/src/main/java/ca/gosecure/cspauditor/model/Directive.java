package ca.gosecure.cspauditor.model;

import java.util.ArrayList;
import java.util.Arrays;
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
        return getName()+": "+ join("",getValues());
    }

    /**
     * In replacement of String.join() from Java 8.
     * @param delimiter the delimiter that separates each element
     * @param elements the elements to join together.
     * @return a new String that is composed of the elements separated by the delimiter
     */
    public static String join(String delimiter, List<String> elements)
    {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < elements.size(); i++)
        {
            sb.append(elements.get(i));
            if(i < elements.size() - 1)
                sb.append(delimiter);
        }
        return sb.toString();
    }
}
